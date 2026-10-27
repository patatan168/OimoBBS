// OTPの署名に相当するコード照合・区間消費の耐久保存・セッション発行を一つの所有mutex内で確定する。
package bootstrap

import (
	"net/http"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

// consumeOTPCodeLocked は同じOTP区間を一度だけ受け付け、保存失敗では認証を許可しない。
func (r *Repository) consumeOTPCodeLocked(a administrator, code string, now time.Time) error {
	security, _, err := r.adminSecurityLocked(a)
	if err != nil {
		return err
	}
	if len(security.OTPSealed) == 0 {
		adminauth.VerifyTOTP(make([]byte, adminauth.TOTPSecretBytes), code, 0, now)
		return &adminFailure{status: 401, code: "OTP_AUTHENTICATION_FAILED"}
	}
	secret, err := r.openOTP(a, security.OTPSealed)
	if err != nil {
		return err
	}
	defer clear(secret)
	next, ok := adminauth.VerifyTOTP(secret, code, uint64(security.NextStep), now)
	if !ok {
		return &adminFailure{status: 401, code: "OTP_AUTHENTICATION_FAILED"}
	}
	security.NextStep = domain.U64(next)
	return r.saveAdminSecurityLocked(a, security, "administrator_otp_used", false)
}

func (h *adminHandler) authenticateOTP(w http.ResponseWriter, r *http.Request, s adminauth.Session, raw, ip, kind string, in otpInput) {
	action, outcome, accountID := "login", "failed", ""
	if kind == "reauth" {
		action = "reauth"
	}
	defer func() { h.security.Record(action, outcome, ip, accountID, time.Now()) }()
	if kind == "login" {
		csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
		nonce, cookieErr := singlePostingCookie(r.Header, "oimo_admin_login", 43)
		if err != nil || cookieErr != nil || !adminLoginName.MatchString(in.Login) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		if err := h.consumeLoginForm(nonce, csrf, ip); err != nil {
			h.failure(w, r, err)
			return
		}
	} else {
		h.repo.mu.Lock()
		a, err := h.repo.currentAdminSession(s)
		h.repo.mu.Unlock()
		if err != nil {
			h.failure(w, r, err)
			return
		}
		in.Login = a.Login
	}
	if err := h.auth.AttemptOTPPassword(ip, time.Now()); err != nil {
		outcome = authenticationOutcome(err)
		h.failure(w, r, err)
		return
	}
	// パスワード導出はRepository mutex外で行い、確定時に同じ世代を再検査する。
	h.repo.mu.Lock()
	a, accountErr := h.otpAccountLocked(s, kind, in.Login)
	h.repo.mu.Unlock()
	var password *adminauth.Password
	if accountErr == nil {
		password = &a.Password
	}
	if len(in.Password) > 512 {
		in.Password = ""
	}
	valid, err := h.auth.Verify(r.Context(), password, in.Password)
	if err != nil {
		outcome = authenticationOutcome(err)
		h.failure(w, r, err)
		return
	}
	if accountErr != nil {
		h.failure(w, r, accountErr)
		return
	}
	if !valid {
		h.fail(w, r, 401, "OTP_AUTHENTICATION_FAILED")
		return
	}
	h.repo.mu.Lock()
	current, err := h.otpAccountLocked(s, kind, in.Login)
	if err == nil && current.Generation != a.Generation {
		err = adminauth.ErrSession
	}
	if err == nil {
		err = h.auth.AttemptOTP(ip, current.Login, time.Now())
	}
	if err == nil {
		err = h.repo.consumeOTPCodeLocked(current, in.Code, time.Now())
	}

	var cookie string
	if err == nil && kind == "login" {
		cookie, _, err = h.auth.Create(a.ID, a.Generation, time.Now())
	}
	if err == nil && kind == "reauth" {
		cookie, _, err = h.auth.MarkStronglyReauthenticated(raw, s, time.Now())
	}
	h.repo.mu.Unlock()
	if err != nil {
		if status := authenticationOutcome(err); status != "error" {
			outcome = status
		} else if failure, ok := err.(*adminFailure); !ok || failure.status >= 500 {
			outcome = "error"
		}
		h.failure(w, r, err)
		return
	}
	http.SetCookie(w, h.adminCookie("oimo_admin", cookie, 8*3600))
	if kind == "login" {
		if old, e := singlePostingCookie(r.Header, "oimo_admin", 43); e == nil {
			h.auth.Delete(old)
		}
		http.SetCookie(w, h.adminCookie("oimo_admin_login", "", -1))
	}
	outcome, accountID = "success", a.ID.String()
	adminJSON(w, 200, map[string]any{"ok": true, "redirect": adminLanding(a)})
}

func (h *adminHandler) otpAccountLocked(s adminauth.Session, kind, login string) (administrator, error) {
	if err := h.repo.available(); err != nil {
		return administrator{}, err
	}
	if kind != "login" {
		return h.repo.currentAdminSession(s)
	}
	accounts, err := h.repo.administrators()
	if err != nil {
		return administrator{}, err
	}
	for _, a := range accounts {
		if a.Login == login && a.Enabled {
			return h.repo.currentAdminAccount(adminauth.Session{Admin: a.ID, Generation: a.Generation})
		}
	}
	return administrator{}, &adminFailure{status: 401, code: "OTP_AUTHENTICATION_FAILED"}
}

func adminLanding(a administrator) string {
	if a.Role == "site_admin" {
		return "/"
	}
	if a.Role == "board_admin" {
		return "/boards"
	}
	return "/auto-reports"
}
