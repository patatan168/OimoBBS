// 管理一覧の有界ページと、経路・取得版・sessionへ束縛した10分カーソル。
package bootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strconv"
	"strings"
	"time"
)

type adminListCursor struct {
	Filter   domain.Hash `json:"filter_hash"`
	Route    string      `json:"route"`
	Revision string      `json:"revision"`
	Last     string      `json:"last"`
	Limit    int         `json:"limit"`
	Expires  string      `json:"expires_at"`
}
type adminListWindow struct {
	Start, End, Limit, Total int
	Next                     string
}

// adminListRoute はqueryを許す一覧経路を固定し、単一対象/変更経路へ転用させない。
func adminListRoute(path string) bool {
	if path == "/auto-reports" || path == "/evidence" || path == "/api/v1/evidence/cases" {
		return true
	}
	if path == "/administrators" || path == "/boards" || path == "/caps" || path == "/api/v1/caps" || path == "/api/v1/administrators" || path == "/api/v1/boards" {
		return true
	}
	path = strings.TrimPrefix(path, "/api/v1")
	if !strings.HasPrefix(path, "/boards/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
	return len(parts) == 2 && (parts[1] == "rules" || parts[1] == "threads") || len(parts) == 4 && parts[1] == "threads" && parts[3] == "moderation"
}

// adminListRevision は担当範囲内の取得結果だけを版に使う。非表示の変更件数を含めない。
func adminListRevision(rows any) (string, error) {
	raw, err := json.Marshal(rows)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// adminListSlice は毎回の現在認可後に呼ぶ。取得結果変更は409、条件変更/改変は400。
func adminListSlice(r *http.Request, session adminauth.Session, revision string, keys []string, now time.Time) (adminListWindow, error) {
	bad := &adminFailure{status: 400, code: "INVALID_LIST_QUERY"}
	if len(r.URL.RawQuery) > 4096 {
		return adminListWindow{}, bad
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return adminListWindow{}, bad
	}
	var listQuery string
	var evidenceFilter evidenceListFilter
	if evidenceListRoute(r.URL.Path) {
		evidenceFilter, err = readEvidenceListFilter(r)
		listQuery = evidenceFilter.Values().Encode()
	} else {
		listQuery, err = adminThreadQuery(r)
	}
	if err != nil {
		return adminListWindow{}, err
	}
	for name, values := range query {
		if evidenceListRoute(r.URL.Path) && (name == "q" || name == "state" || name == "sort" || name == "kind") || name == "q" && adminThreadListRoute(r.URL.Path) {
			continue
		}
		if (name != "limit" && name != "cursor") || len(values) != 1 || values[0] == "" {
			return adminListWindow{}, bad
		}
	}
	limit, start := 50, 0
	expires := now.Add(10 * time.Minute)
	if value, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(value[0])
		if err != nil || limit < 1 || limit > 200 || strconv.Itoa(limit) != value[0] {
			return adminListWindow{}, bad
		}
	}
	if value, ok := query["cursor"]; ok {
		parts := strings.Split(value[0], ".")
		if len(parts) != 2 || !session.CheckCSRF("admin-list-cursor:"+parts[0], parts[1]) {
			return adminListWindow{}, bad
		}
		raw, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
		if e != nil || base64.RawURLEncoding.EncodeToString(raw) != parts[0] {
			return adminListWindow{}, bad
		}
		var cursor adminListCursor
		if strictjson.Decode(raw, &cursor) != nil || cursor.Route != r.URL.Path || cursor.Last == "" || cursor.Limit < 1 || cursor.Limit > 200 || cursor.Filter != adminListQueryFilter(cursor.Route, cursor.Limit, listQuery) {
			return adminListWindow{}, bad
		}
		if _, set := query["limit"]; set && limit != cursor.Limit {
			return adminListWindow{}, bad
		}
		limit = cursor.Limit
		expires, err = time.Parse(time.RFC3339Nano, cursor.Expires)
		if err != nil || expires.After(now.Add(10*time.Minute)) {
			return adminListWindow{}, bad
		}
		if !now.Before(expires) || cursor.Revision != revision {
			return adminListWindow{}, &adminFailure{status: 409, code: "LIST_VERSION_EXPIRED"}
		}
		found := false
		for index, key := range keys {
			if key == cursor.Last {
				start = index + 1
				found = true
				break
			}
		}
		if !found || start >= len(keys) {
			return adminListWindow{}, &adminFailure{status: 409, code: "LIST_VERSION_EXPIRED"}
		}
	}
	end := min(start+limit, len(keys))
	window := adminListWindow{Start: start, End: end, Limit: limit, Total: len(keys)}
	if end < len(keys) {
		cursor := adminListCursor{Filter: adminListQueryFilter(r.URL.Path, limit, listQuery), Route: r.URL.Path, Revision: revision, Last: keys[end-1], Limit: limit, Expires: expires.UTC().Format(time.RFC3339Nano)}
		raw, e := json.Marshal(cursor)
		if e != nil {
			return adminListWindow{}, e
		}
		encoded := base64.RawURLEncoding.EncodeToString(raw)
		window.Next = encoded + "." + session.CSRF("admin-list-cursor:"+encoded)
	}
	return window, nil
}

// listMetadata は既存data形を保ち、有界ページの契約を外側へ追加する。
func listMetadata(data any, page adminListWindow, revision string) map[string]any {
	return map[string]any{"data": data, "limit": page.Limit, "next_cursor": page.Next, "revision": revision, "request_id": domain.NewID()}
}

func adminListFilter(route string, limit int) domain.Hash {
	return sha256.Sum256([]byte(route + "?limit=" + strconv.Itoa(limit)))
}

// adminNextLink は経路・sessionへ束縛したcursorを同じHTML一覧の次ページへ接続する。
func adminNextLink(path string, window adminListWindow) string {
	if window.Next == "" {
		return ""
	}
	return path + "?" + url.Values{"cursor": {window.Next}}.Encode()
}
