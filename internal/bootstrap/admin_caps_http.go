// キャップ一覧・発行・停止のAPI/画面を同じ認可と保存経路へ接続する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"slices"
	"strconv"
	"strings"
	"time"
)

type capRow struct {
	AdminCap
	UpdateCSRF, UpdateRequestID string
	ResetCSRF                   string
	ResetRequestID              string
	CSRF                        string
	RequestID                   string
}
type capsPage struct {
	Boards                                          []boardOption
	Rows                                            []capRow
	CSRF, ETag, RequestID, Secret, Credential, Next string
	Saved                                           *AdminCap
}

var capsTemplate = webui.Template("caps")

// capsRoutes は利用者入力名をpathに使わず、固定IDの資格だけを発行/停止する。
func (h *adminHandler) capsRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	api := strings.HasPrefix(r.URL.Path, "/api/")
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	var target domain.ID
	revoke := false
	reset := false
	update := false
	if path != "/caps" {
		parts := strings.Split(strings.TrimPrefix(path, "/caps/"), "/")
		if len(parts) < 1 || len(parts) > 2 || json.Unmarshal([]byte(strconv.Quote(parts[0])), &target) != nil || target == (domain.ID{}) || len(parts) == 2 && parts[1] != "revoke" && parts[1] != "reset" && parts[1] != "update" {
			h.fail(w, r, 404, "NOT_FOUND")
			return
		}
		revoke = len(parts) == 2
		update = revoke && parts[1] == "update"
		reset = revoke && (parts[1] == "reset" || update)
	}
	if r.Method == "GET" && !revoke {
		rows, seq, window, e := h.repo.adminCapsSelection(s, r, target)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		etag, csrf := capListETag(seq), s.CSRF("/api/v1/caps")
		page := capsPage{Rows: []capRow{}, CSRF: csrf, ETag: etag, RequestID: domain.NewID().String()}
		for _, v := range rows {
			page.Rows = append(page.Rows, capRow{AdminCap: v, UpdateCSRF: s.CSRF("/api/v1/caps/" + v.ID.String() + "/update"), UpdateRequestID: domain.NewID().String(), ResetRequestID: domain.NewID().String(), ResetCSRF: s.CSRF("/api/v1/caps/" + v.ID.String() + "/reset"), CSRF: s.CSRF("/api/v1/caps/" + v.ID.String() + "/revoke"), RequestID: domain.NewID().String()})
			if v.ID == target {
				view := v
				page.Saved = &view
				etag = v.ETag()
				csrf = s.CSRF("/api/v1/caps/" + v.ID.String() + "/revoke")
			}
		}
		if target != (domain.ID{}) && page.Saved == nil {
			h.fail(w, r, 404, "CAP_NOT_FOUND")
			return
		}
		w.Header().Set("ETag", etag)
		if api {
			w.Header().Set("X-CSRF-Token", csrf)
			if target != (domain.ID{}) {
				w.Header().Set("X-CSRF-Reset-Token", s.CSRF("/api/v1/caps/"+target.String()+"/reset"))
				w.Header().Set("X-CSRF-Update-Token", s.CSRF("/api/v1/caps/"+target.String()+"/update"))
			}
			var data any = capHTTPValues(rows)
			if page.Saved != nil {
				data = capHTTPValue(*page.Saved)
			}
			if target == (domain.ID{}) {

				adminJSON(w, 200, listMetadata(capHTTPValues(rows), window, etag))
				return
			}
			adminJSON(w, 200, map[string]any{"data": data})
			return
		}
		if window.Next != "" {
			page.Next = "/caps?" + url.Values{"cursor": {window.Next}}.Encode()
		}
		page.Boards, e = h.repo.boardOptions(s, nil)
		if e != nil {
			h.failure(w, r, e)
			return
		}
		writeCapsPage(w, page)
		return
	}
	if r.Method != "POST" || target != (domain.ID{}) && !revoke {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var input capInput
	var csrf, etag, key string
	if api {
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, err := mime.ParseMediaType(typ)
		if e != nil || err != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, e = singleRequestHeader(r.Header, "If-Match")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, e = singleRequestHeader(r.Header, "Idempotency-Key")
		if e != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		if !s.CheckCSRF("/api/v1"+path, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
		if e != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		if revoke && !update {
			var empty struct{}
			e = strictjson.Decode(raw, &empty)
		} else {
			e = strictjson.Decode(raw, &input)
		}
		if e != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		allowed := []string{"csrf", "revision", "request_id"}
		if !revoke || update {
			allowed = append(allowed, "display_name", "board_ids", "permissions", "expires_at")
		}
		fields, e := adminForm(w, r, 32<<10, allowed...)
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		csrf, etag, key = fields.Get("csrf"), fields.Get("revision"), fields.Get("request_id")
		if !revoke || update {
			input.Name = fields.Get("display_name")
			input.Boards = []domain.ID{}
			input.Permissions = strings.Fields(fields.Get("permissions"))
			if fields.Get("expires_at") != "" {
				expires, e := parseCapExpiryForm(fields.Get("expires_at"))
				if e != nil || expires.Year() < 1970 || expires.Year() > 2261 {
					h.fail(w, r, 422, "INVALID_EXPIRY")
					return
				}
				input.Expires = domain.Time(expires.UnixNano())
			}
			for _, raw := range strings.Fields(fields.Get("board_ids")) {
				var id domain.ID
				if json.Unmarshal([]byte(strconv.Quote(raw)), &id) != nil {
					h.fail(w, r, 422, "INVALID_BOARD")
					return
				}
				input.Boards = append(input.Boards, id)
			}
		}
	}
	if !s.CheckCSRF("/api/v1"+path, csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	view, secret, e := h.repo.changeCapOperation(s, target, input, etag, key, reset, update)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	w.Header().Set("ETag", view.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": capHTTPValue(view), "secret": secret, "secret_available": secret != ""})
		return
	}
	page := capsPage{Saved: &view, Secret: secret}
	if secret != "" {
		page.Credential = "#cap:" + view.ID.String() + ":" + secret
	}
	writeCapsPage(w, page)
}

// writeCapsPage はテンプレートを先に検査し、失敗時に部分的な成功画面を返さない。
func writeCapsPage(w http.ResponseWriter, page capsPage) {
	var body bytes.Buffer
	if e := executeAdminTemplate(w, &body, capsTemplate, page); e != nil {
		http.Error(w, "管理画面を作成できませんでした", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_, _ = body.WriteTo(w)
}

// BoardLabel は一覧の内部IDを管理者が識別できる板名へ変換する。
func (p capsPage) BoardLabel(id domain.ID) string {
	for _, b := range p.Boards {
		if b.ID == id {
			return b.Name + "（" + b.Key + "）"
		}
	}
	return id.String()
}

// parseCapExpiryForm は日時選択欄を日本時間として読み、旧フォームのRFC3339も受け付ける。
func parseCapExpiryForm(raw string) (time.Time, error) {
	if value, err := time.Parse(time.RFC3339, raw); err == nil {
		return value, nil
	}
	if value, err := time.ParseInLocation("2006-01-02T15:04", raw, domain.JST); err == nil {
		return value, nil
	}
	return time.ParseInLocation("2006-01-02T15:04:05.999999999", raw, domain.JST)
}

// BoardChosen は更新画面の現在の担当板を示す。
func (v capRow) BoardChosen(id domain.ID) bool { return slices.Contains(v.Boards, id) }

// PermissionChosen は更新画面の現在の許可を示す。
func (v capRow) PermissionChosen(permission string) bool {
	return slices.Contains(v.Permissions, permission)
}

// ExpiryInput は保存済みの期限を日本時間の日時入力へ精度を保って変換する。
func (v capRow) ExpiryInput() string {
	if v.Expires == 0 {
		return ""
	}
	return time.Unix(0, int64(v.Expires)).In(domain.JST).Format("2006-01-02T15:04:05.999999999")
}
