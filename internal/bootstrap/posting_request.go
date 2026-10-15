// 直結legacy投稿のHTTP境界。公開ルーターへ登録する前の内部アダプタ。
package bootstrap

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"strings"
)

var ErrPostingRequest = errors.New("invalid posting request boundary")

// SubmitLegacyRequest は設定済みHost/origin、単値ヘッダ、確認Cookieを検査してから本文を読む。
// observerのConnContextを設定した直結server専用。製品serve・規制は未接続。WebはSubmitWebRequestを使う。
func (repo *Repository) SubmitLegacyRequest(r *http.Request, owner domain.ID, observer *evidence.HTTPObserver) LegacyFormResult {
	token, e := checkLegacyRequest(r, repo.cfg.Public.BaseURL)
	if e != nil {
		return legacyFailure(e)
	}
	anon, e := repo.anonymousRequestCookie(r.Header)
	if e != nil {
		return legacyFailure(e)
	}
	origin, e := parseOrigin(repo.cfg.Public.BaseURL)
	if e != nil {
		return legacyFailure(e)
	}
	capture, e := observer.Begin(r, owner, "bbs_post", origin.Host)
	if e != nil {
		return legacyFailure(e)
	}
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return legacyFailure(e)
	}
	observation, e := capture.Finish()
	if e != nil {
		return legacyFailure(e)
	}
	contentType, _, e := singleRequestHeader(r.Header, "Content-Type")
	if e != nil {
		return legacyFailure(e)
	}
	return repo.submitForm(r.Context(), owner, body, contentType, observation, token, "", false, anon)
}

func checkLegacyRequest(r *http.Request, base string) (string, error) {
	return checkPostingRequest(r, base, false)
}

// checkPostingRequest はWebとブラウザで投稿元を必須にし、legacy専ブラだけヘッダ省略を許す。
func checkPostingRequest(r *http.Request, base string, web bool) (string, error) {
	path := "/test/bbs.cgi"
	if web {
		path = "/web/post"
	}
	if r == nil || r.URL == nil || r.Body == nil || r.Method != "POST" || r.URL.EscapedPath() != path {
		return "", ErrPostingRequest
	}
	configured, e := parseOrigin(base)
	if e != nil {
		return "", ErrPostingRequest
	}
	if (configured.Scheme == "https") != (r.TLS != nil) {
		return "", ErrPostingRequest
	}
	host, e := parseOrigin(configured.Scheme + "://" + r.Host)
	if e != nil || normalizedOrigin(host) != normalizedOrigin(configured) {
		return "", ErrPostingRequest
	}
	origin, present, e := singleRequestHeader(r.Header, "Origin")
	if e != nil {
		return "", e
	}
	if present {
		u, e := parseOrigin(origin)
		if e != nil || normalizedOrigin(u) != normalizedOrigin(configured) {
			return "", ErrPostingRequest
		}
	}
	referer, hasReferer, e := singleRequestHeader(r.Header, "Referer")
	if e != nil {
		return "", e
	}
	if web && !present && !hasReferer {
		return "", ErrPostingRequest
	}
	if !present && hasReferer {
		u, e := url.Parse(referer)
		if e != nil || u.User != nil || u.Fragment != "" || u.Opaque != "" || u.Host == "" {
			return "", ErrPostingRequest
		}
		ref, e := parseOrigin(u.Scheme + "://" + u.Host)
		if e != nil || normalizedOrigin(ref) != normalizedOrigin(configured) {
			return "", ErrPostingRequest
		}
	}
	fetch, hasFetch, e := singleRequestHeader(r.Header, "Sec-Fetch-Site")
	if e != nil {
		return "", e
	}
	if hasFetch && (fetch != "same-origin" && fetch != "none" || !present && !hasReferer) {
		return "", ErrPostingRequest
	}
	_, hasType, e := singleRequestHeader(r.Header, "Content-Type")
	if e != nil || !hasType {
		return "", ErrPostingRequest
	}
	encoding, hasEncoding, e := singleRequestHeader(r.Header, "Content-Encoding")
	if e != nil || hasEncoding && encoding != "identity" {
		return "", ErrPostingRequest
	}
	return confirmationCookie(r.Header)
}

// singleRequestHeader はパーサ外で構築されたHeaderも含め、大小文字違いの重複を拒否する。
func singleRequestHeader(h http.Header, name string) (string, bool, error) {
	var value string
	found := false
	for k, values := range h {
		if !strings.EqualFold(k, name) {
			continue
		}
		if found || len(values) != 1 {
			return "", false, ErrPostingRequest
		}
		found = true
		value = values[0]
	}
	if found && value == "" {
		return "", false, ErrPostingRequest
	}
	return value, found, nil
}

// confirmationCookie は同名重複・壊れた確認Cookieを曖昧に選ばず拒否する。未知Cookieは保存しない。
func confirmationCookie(h http.Header) (string, error) {
	return singlePostingCookie(h, "oimo_confirm", 320)
}

// singlePostingCookie は対象Cookieだけを取り出し、重複と非正規文字を拒否する。
func singlePostingCookie(h http.Header, cookieName string, limit int) (string, error) {
	value := ""
	found := false
	for k, lines := range h {
		if !strings.EqualFold(k, "Cookie") {
			continue
		}
		for _, line := range lines {
			for _, part := range strings.Split(line, ";") {
				name, token, ok := strings.Cut(strings.TrimSpace(part), "=")
				if strings.TrimSpace(name) != cookieName {
					continue
				}
				if name != cookieName || found || !ok || len(token) == 0 || len(token) > limit {
					return "", ErrPostingRequest
				}
				for _, c := range token {
					if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
						return "", ErrPostingRequest
					}
				}
				value = token
				found = true
			}
		}
	}
	return value, nil
}
