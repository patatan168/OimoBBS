// 管理スレッド一覧のタイトル条件をHTML/APIと署名cursorへ共用する。
package bootstrap

import (
	"crypto/sha256"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"oimobbs/internal/domain"
)

func adminThreadListRoute(path string) bool {
	path = strings.TrimPrefix(path, "/api/v1")
	parts := strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
	return strings.HasPrefix(path, "/boards/") && len(parts) == 2 && parts[1] == "threads"
}

// adminThreadQuery は単一のUTF-8条件だけを受け付け、本文や非公開の元タイトルを検索しない。
func adminThreadQuery(r *http.Request) (string, error) {
	bad := &adminFailure{status: 400, code: "INVALID_LIST_QUERY"}
	if len(r.URL.RawQuery) > 4096 {
		return "", bad
	}
	v, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return "", bad
	}
	if values, exists := v["q"]; exists && (len(values) != 1 || !adminThreadListRoute(r.URL.Path)) {
		return "", bad
	}
	q := v.Get("q")
	if !utf8.ValidString(q) || utf8.RuneCountInString(q) > 128 || len(strings.Fields(q)) > 8 {
		return "", bad
	}
	return q, nil
}

func adminThreadMatches(title, query string) bool {
	for _, term := range strings.Fields(query) {
		if !containsASCIIFold(title, asciiFold(term)) {
			return false
		}
	}
	return true
}

func adminListQueryFilter(route string, limit int, query string) domain.Hash {
	if query == "" {
		return adminListFilter(route, limit)
	}
	return sha256.Sum256([]byte(route + "?" + url.Values{"limit": {strconv.Itoa(limit)}, "q": {query}}.Encode()))
}

// adminThreadNextLink は次ページにも同じタイトル条件を渡す。
func adminThreadNextLink(path string, window adminListWindow, query string) string {
	if window.Next == "" {
		return ""
	}
	v := url.Values{"cursor": {window.Next}}
	if query != "" {
		v.Set("q", query)
	}
	return path + "?" + v.Encode()
}
