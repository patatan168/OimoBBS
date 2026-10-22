// 重要操作用の再認証。パスワード導出中に所有mutexを保持せず、確定時に世代を再検査する。
package bootstrap

import (
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"strconv"
)

// reauthenticate は入力専用秘密を照合し、既存セッションに10分の再認証状態を設定する。
func (h *adminHandler) reauthenticate(w http.ResponseWriter, r *http.Request, raw string, s adminauth.Session, ip string) {
	outcome := "rejected"
	defer func() {
		if r.Method != "GET" {
			h.security.Record("reauth", outcome, ip, s.Admin.String(), time.Now())
		}
	}()
	h.repo.mu.Lock()
	accountPolicy, policyErr := h.repo.currentAdminSession(s)
	var security adminSecurityState
	if policyErr == nil {
		security, _, policyErr = h.repo.adminSecurityLocked(accountPolicy)
	}
	h.repo.mu.Unlock()
	if policyErr != nil {
		h.failure(w, r, policyErr)
		return
	}
	api := strings.HasPrefix(r.URL.Path, "/api/")
	const route = "/api/v1/reauth"
	if r.Method == "GET" {
		if api {
			w.Header().Set("X-CSRF-Token", s.CSRF(route))
			adminJSON(w, 200, map[string]any{"reauthenticated": s.Reauthenticated(time.Now()), "valid_for_seconds": int(adminauth.ReauthenticationValidity / time.Second)})
			return
		}
		writeAdminPage(w, 200, adminPage{Title: "管理者の再認証", Reauth: true, PasswordDisabled: security.PasswordDisabled, OTPCSRF: s.CSRF(otpRoute), OTPEnabled: len(security.OTPSealed) > 0, PasskeyCSRF: s.CSRF(passkeyRoute), CSRF: s.CSRF(route), BackPath: reauthReturnPath(r)})
		return
	}
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if security.PasswordDisabled || len(security.OTPSealed) > 0 {
		h.fail(w, r, 403, "PASSWORD_AUTHENTICATION_DISABLED")
		return
	}
	var secret, csrf string
	if api {
		typ, _, e := singleRequestHeader(r.Header, "Content-Type")
		media, _, err := mime.ParseMediaType(typ)
		if e != nil || err != nil || media != "application/json" {
			h.fail(w, r, 415, "JSON_REQUIRED")
			return
		}
		csrf, _, e = singleRequestHeader(r.Header, "X-CSRF-Token")
		if e != nil || !s.CheckCSRF(route, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
		var input struct {
			Password string `json:"password"`
		}
		if e != nil || strictjson.Decode(body, &input) != nil {
			h.fail(w, r, 400, "INVALID_JSON")
			return
		}
		secret = input.Password
	} else {
		fields, e := adminForm(w, r, 8<<10, "password", "csrf")
		if e != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		secret, csrf = fields.Get("password"), fields.Get("csrf")
	}
	if !s.CheckCSRF(route, csrf) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	if len(secret) == 0 || len(secret) > 512 {
		h.fail(w, r, 400, "INVALID_PASSWORD")
		return
	}
	h.repo.mu.Lock()
	account, e := h.repo.currentAdminSession(s)
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	if e = h.auth.AttemptPassword(ip, time.Now()); e != nil {
		outcome = authenticationOutcome(e)
		h.failure(w, r, e)
		return
	}
	valid, e := h.auth.Verify(r.Context(), &account.Password, secret)
	if e != nil {
		outcome = authenticationOutcome(e)
		h.failure(w, r, e)
		return
	}
	if !valid {
		outcome = "failed"
		if !api {
			writeAdminPage(w, 401, adminPage{Title: "管理者の再認証", Message: "パスワードが一致しません。もう一度入力してください。", Reauth: true, PasswordDisabled: security.PasswordDisabled, OTPCSRF: s.CSRF(otpRoute), OTPEnabled: len(security.OTPSealed) > 0, PasskeyCSRF: s.CSRF(passkeyRoute), CSRF: s.CSRF(route), BackPath: reauthReturnPath(r)})
			return
		}
		h.fail(w, r, 401, "REAUTHENTICATION_FAILED")
		return
	}
	var cookie string
	h.repo.mu.Lock()
	current, checkErr := h.repo.currentAdminSession(s)
	e = checkErr
	if e == nil {
		policy, _, err := h.repo.adminSecurityLocked(current)
		if err != nil {
			e = err
		} else if policy.PasswordDisabled || len(policy.OTPSealed) > 0 {
			e = &adminFailure{status: 403, code: "PASSWORD_AUTHENTICATION_DISABLED"}
		}
	}
	if e == nil {
		cookie, _, e = h.auth.MarkReauthenticated(raw, s, time.Now())
	}
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, e)
		return
	}
	http.SetCookie(w, h.adminCookie("oimo_admin", cookie, 8*3600))
	outcome = "success"
	if api {
		adminJSON(w, 200, map[string]any{"reauthenticated": true, "valid_for_seconds": int(adminauth.ReauthenticationValidity / time.Second)})
		return
	}
	http.Redirect(w, r, reauthReturnPath(r), 303)
}

// adminReturnPath は管理GET画面だけを戻り先として許可し、外部URLと更新専用経路を除く。
func adminReturnPath(path string) string {
	if path == "/auto-reports" {
		return path
	}
	if strings.HasPrefix(path, "/auto-reports/") {
		parts := strings.Split(strings.TrimPrefix(path, "/auto-reports/"), "/")
		var board, rule domain.ID
		if len(parts) == 2 && board.UnmarshalJSON([]byte(strconv.Quote(parts[0]))) == nil && rule.UnmarshalJSON([]byte(strconv.Quote(parts[1]))) == nil && board != (domain.ID{}) && rule != (domain.ID{}) {
			return path
		}
	}
	if _, _, parts, ok := adminPostsPath(path); ok && len(parts) == 5 {
		n, err := strconv.ParseUint(parts[4], 10, 32)
		if err == nil && n > 0 && strconv.FormatUint(n, 10) == parts[4] {
			return path
		}
	}
	if path == "/passkeys" {
		return path
	}
	if path == "/caps" || strings.HasPrefix(path, "/caps/") {
		return "/caps"
	}
	if path == "/terms" || path == "/administrators" || path == "/waf" {
		return path
	}
	if strings.HasPrefix(path, "/administrators/") {
		var id domain.ID
		if id.UnmarshalJSON([]byte(strconv.Quote(strings.TrimPrefix(path, "/administrators/")))) == nil {
			return path
		}
	}
	if strings.HasPrefix(path, "/evidence/") {
		return "/evidence"
	}
	if path == "/evidence" || path == "/boards" || path == "/networks" || path == "/anonymous" || path == "/audit" || path == "/" {
		return path
	}
	return "/"
}

// reauthReturnPath はフォームactionのクエリから安全な戻り先を引き継ぐ。
func reauthReturnPath(r *http.Request) string { return adminReturnPath(r.URL.Query().Get("return_to")) }

// ReauthAction は再認証完了後の画面をフォーム送信にも保持する。
func (p adminPage) ReauthAction() string {
	return "/reauth?" + url.Values{"return_to": {p.BackPath}}.Encode()
}

// ReauthDestination は許可済みの戻り先を利用者向けの画面名に変換する。
func (p adminPage) ReauthDestination() string {
	switch p.BackPath {
	case "/passkeys":
		return "パスキー管理"
	case "/evidence":
		return "提出用ログ"
	case "/boards":
		return "板設定"
	case "/caps":
		return "キャップ管理"
	case "/networks":
		return "ネットワーク規制"
	case "/anonymous":
		return "匿名利用者の管理"
	case "/audit":
		return "管理操作の記録"
	}
	if _, _, _, ok := adminPostsPath(p.BackPath); ok {
		return "レスの管理"
	}
	if p.BackPath == "/auto-reports" || strings.HasPrefix(p.BackPath, "/auto-reports/") {
		return "自動停止・通報確認"
	}
	if strings.HasPrefix(p.BackPath, "/administrators") {
		return "管理者の権限設定"
	}
	return "サイト設定"
}

// validReauthQuery は再認証画面に限り戻り先一件のクエリを受け付ける。
func validReauthQuery(r *http.Request) bool {
	if r.URL.Path != "/reauth" || r.Method != "GET" && r.Method != "POST" {
		return false
	}
	v, e := url.ParseQuery(r.URL.RawQuery)
	return e == nil && len(v) == 1 && len(v["return_to"]) == 1
}
