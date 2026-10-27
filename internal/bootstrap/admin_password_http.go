// 一時パスワードを一度だけ表示し、制限セッションには本人のパスワード変更だけを許可する。
package bootstrap

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
)

type passwordPage struct {
	CSRF, Temporary, Login string
	Issued                 bool
}

var passwordTemplate = webui.Template("password")

func writePasswordPage(w http.ResponseWriter, page passwordPage) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_ = executeAdminTemplate(w, w, passwordTemplate, page)
}

func (h *adminHandler) passwordRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session, raw, ip string) {
	const route = "/api/v1/password"
	h.repo.mu.Lock()
	a, err := h.repo.authenticatedAdminSession(s)
	var security adminSecurityState
	if err == nil {
		security, _, err = h.repo.adminSecurityLocked(a)
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if a.Role == "site_admin" || !security.PasswordChangeRequired {
		h.fail(w, r, 403, "PASSWORD_CHANGE_NOT_REQUIRED")
		return
	}
	if r.Method == "GET" {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]bool{"password_change_required": true})
		} else {
			writePasswordPage(w, passwordPage{CSRF: s.CSRF(route)})
		}
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	var current, next, csrf string
	if strings.HasPrefix(r.URL.Path, "/api/") {
		typ, _, err := singleRequestHeader(r.Header, "Content-Type")
		media, _, parseErr := mime.ParseMediaType(typ)
		if err != nil || parseErr != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		csrf, _, err = singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		var in struct {
			Current string `json:"current_password"`
			Next    string `json:"new_password"`
		}
		if err != nil || strictjson.Decode(body, &in) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		current, next = in.Current, in.Next
	} else {
		fields, err := adminForm(w, r, 8<<10, "current_password", "new_password", "csrf")
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		current, next, csrf = fields.Get("current_password"), fields.Get("new_password"), fields.Get("csrf")
	}
	if !s.CheckCSRF(route, csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	if len(current) > 512 || len(next) > 512 {
		h.fail(w, r, 400, "INVALID_PASSWORD")
		return
	}
	if err := h.auth.AttemptPassword(ip, time.Now()); err != nil {
		h.failure(w, r, err)
		return
	}
	if err := h.repo.changeOwnPassword(r.Context(), s, current, next, time.Now()); err != nil {
		h.failure(w, r, err)
		return
	}
	h.auth.Delete(raw)
	http.SetCookie(w, h.adminCookie("oimo_admin", "", -1))
	if strings.HasPrefix(r.URL.Path, "/api/") {
		adminJSON(w, 200, map[string]any{"ok": true, "redirect": "/login"})
	} else {
		http.Redirect(w, r, "/login", 303)
	}
}

func (h *adminHandler) temporaryPasswordRoute(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	path := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1"), "/password-reset")
	var target domain.ID
	encoded, _ := json.Marshal(strings.TrimPrefix(path, "/administrators/"))
	if json.Unmarshal(encoded, &target) != nil || target == (domain.ID{}) {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	route := "/api/v1/administrators/" + target.String() + "/password-reset"
	var etag, key, csrf string
	if strings.HasPrefix(r.URL.Path, "/api/") {
		typ, _, err := singleRequestHeader(r.Header, "Content-Type")
		media, _, parseErr := mime.ParseMediaType(typ)
		if err != nil || parseErr != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		var readErr error
		csrf, _, readErr = singleRequestHeader(r.Header, "X-CSRF-Token")
		if readErr != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		etag, _, err = singleRequestHeader(r.Header, "If-Match")
		if err != nil {
			h.fail(w, r, 400, "INVALID_REVISION")
			return
		}
		key, _, err = singleRequestHeader(r.Header, "Idempotency-Key")
		if err != nil {
			h.fail(w, r, 400, "INVALID_REQUEST_KEY")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1024))
		if err != nil || strictjson.Decode(body, &struct{}{}) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
	} else {
		fields, err := adminForm(w, r, 4096, "csrf", "revision", "request_id")
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		csrf, etag, key = fields.Get("csrf"), fields.Get("revision"), fields.Get("request_id")
	}
	if !s.CheckCSRF(route, csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	temporary, err := h.repo.resetTemporaryPassword(s, target, etag, key)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		adminJSON(w, 200, map[string]any{"temporary_password": temporary, "expires_in": 3600, "password_change_required": true})
	} else {
		writePasswordPage(w, passwordPage{Issued: true, Temporary: temporary})
	}
}
