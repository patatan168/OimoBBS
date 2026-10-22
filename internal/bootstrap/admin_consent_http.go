// 規約編集フォーム/APIへ経路別CSRFと厳密な入力検証を適用する。
package bootstrap

import (
	"io"
	"mime"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"strings"
)

var consentTemplate = webui.Template("consent")

type consentPage struct {
	State                    AdminConsent
	CSRF, RequestID, Message string
}

func (h *adminHandler) writeConsentPage(w http.ResponseWriter, r *http.Request, s adminauth.Session, v AdminConsent, status int, message string) {
	page := consentPage{v, s.CSRF("/api/v1/terms"), domain.NewID().String(), message}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_ = executeAdminTemplate(w, w, consentTemplate, page)
}
func (h *adminHandler) consentRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	const route = "/api/v1/terms"
	api := strings.HasPrefix(r.URL.Path, "/api/v1/")
	current, e := h.repo.adminConsent(s)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	if r.Method == "GET" {
		w.Header().Set("ETag", current.ETag())
		w.Header().Set("X-CSRF-Token", s.CSRF(route))
		if api {
			adminJSON(w, 200, map[string]any{"data": current})
			return
		}
		h.writeConsentPage(w, r, s, current, 200, "")
		return
	}
	if (!api && r.Method != "POST") || (api && r.Method != "PATCH") {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var text ConsentText
	var etag, key string
	if api {
		csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(route, csrf) {
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
		typ, _, err := singleRequestHeader(r.Header, "Content-Type")
		media, _, parseErr := mime.ParseMediaType(typ)
		if err != nil || parseErr != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil || strictjson.Decode(raw, &text) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		fields, err := adminForm(w, r, 192<<10, "cookie_notice", "terms_text", "revision", "request_id", "csrf")
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(route, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		text = ConsentText{fields.Get("cookie_notice"), fields.Get("terms_text")}
		etag, key = fields.Get("revision"), fields.Get("request_id")
	}
	result, e := h.repo.updateConsent(s, text, etag, key)
	if e != nil {
		if !api {
			if f, ok := e.(*adminFailure); ok && f.status == 422 {
				current.Consent.CookieNotice = text.CookieNotice
				current.Consent.TermsText = text.TermsText
				h.writeConsentPage(w, r, s, current, 422, "空欄や文字数を確認してください。Cookie説明は4KiB、利用規約は24KiBまでです。")
				return
			}
		}
		h.failure(w, r, e)
		return
	}
	w.Header().Set("ETag", result.ETag())
	if api {
		adminJSON(w, 200, map[string]any{"data": result})
		return
	}
	http.Redirect(w, r, "/terms", 303)
}
