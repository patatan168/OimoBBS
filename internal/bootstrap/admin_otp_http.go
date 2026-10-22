// 本人のOTP登録・解除・パスワード禁止方針をOrigin・CSRF・再認証と接続する。
package bootstrap

import (
	"crypto/rand"
	"encoding/base32"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

const otpRoute = "/api/v1/otp/"

type otpChangeResult struct {
	Data               any
	SetupToken         string
	ClearSetup, Logout bool
}

type otpInput struct {
	Login, Code, Password string
	PasswordDisabled      bool
}

func decodeOTPInput(raw []byte, kind string) (otpInput, error) {
	switch kind {
	case "login":
		var v struct {
			Login    string `json:"login"`
			Code     string `json:"code"`
			Password string `json:"password"`
		}
		err := strictjson.Decode(raw, &v)
		return otpInput{Login: v.Login, Code: v.Code, Password: v.Password}, err
	case "reauth":
		var v struct {
			Code     string `json:"code"`
			Password string `json:"password"`
		}
		err := strictjson.Decode(raw, &v)
		return otpInput{Code: v.Code, Password: v.Password}, err
	case "register/finish":
		var v struct {
			Code string `json:"code"`
		}
		err := strictjson.Decode(raw, &v)
		return otpInput{Code: v.Code}, err
	case "policy":
		var v struct {
			Disabled bool `json:"password_disabled"`
		}
		err := strictjson.Decode(raw, &v)
		return otpInput{PasswordDisabled: v.Disabled}, err
	default:
		return otpInput{}, strictjson.Decode(raw, &struct{}{})
	}
}

func (h *adminHandler) otpRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session, raw, ip string) {
	kind := strings.TrimPrefix(r.URL.Path, otpRoute)
	if r.Method == "GET" && kind == "register/qr" {
		h.otpQR(w, r, s, raw)
		return
	}
	if r.Method != "POST" || kind != "login" && kind != "reauth" && kind != "register/begin" && kind != "register/finish" && kind != "remove" && kind != "policy" {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	if kind != "login" {
		csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
		if err != nil || !s.CheckCSRF(otpRoute, csrf) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
	}
	typ, _, err := singleRequestHeader(r.Header, "Content-Type")
	media, _, parseErr := mime.ParseMediaType(typ)
	if err != nil || parseErr != nil || media != "application/json" {
		h.fail(w, r, 415, "JSON_REQUIRED")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
	in, decodeErr := decodeOTPInput(body, kind)
	if err != nil || decodeErr != nil {
		h.fail(w, r, 400, "INVALID_JSON")
		return
	}
	if kind == "login" || kind == "reauth" {
		h.authenticateOTP(w, r, s, raw, ip, kind, in)
		return
	}
	if !s.Reauthenticated(time.Now()) {
		h.fail(w, r, 403, "REAUTHENTICATION_REQUIRED")
		return
	}
	h.repo.mu.Lock()
	a, err := h.repo.currentAdminSession(s)
	var security adminSecurityState
	var revision domain.U64
	if err == nil {
		security, revision, err = h.repo.adminSecurityLocked(a)
	}
	if err == nil {
		if kind == "register/finish" {
			err = h.auth.AttemptOTP(ip, a.Login, time.Now())
		} else {
			err = h.auth.AttemptSecuritySetting(ip, time.Now())
		}
	}
	var result otpChangeResult
	if err == nil {
		err = h.changeOTP(&result, r.Header, s, raw, kind, in, a, security, revision)
	}
	h.repo.mu.Unlock()
	if result.ClearSetup {
		http.SetCookie(w, h.adminCookie("oimo_admin_otp", "", -1))
	}
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if result.SetupToken != "" {
		http.SetCookie(w, h.adminCookie("oimo_admin_otp", result.SetupToken, 120))
	}
	if result.Logout {
		http.SetCookie(w, h.adminCookie("oimo_admin", "", -1))
	}
	adminJSON(w, 200, result.Data)
}

// changeOTP は本人確認と最新世代を検査した所有mutex内でのみ設定を変更する。
func (h *adminHandler) changeOTP(result *otpChangeResult, headers http.Header, s adminauth.Session, binding, kind string, in otpInput, a administrator, security adminSecurityState, revision domain.U64) error {
	switch kind {
	case "register/begin":
		if len(security.OTPSealed) > 0 {
			return &adminFailure{status: 409, code: "OTP_ALREADY_ENABLED"}
		}
		pending := &otpEnrollment{Binding: binding, Admin: a.ID, Generation: a.Generation, Revision: revision}
		secretBytes := make([]byte, adminauth.TOTPSecretBytes)
		defer clear(secretBytes)
		if _, err := rand.Read(secretBytes); err != nil {
			return err
		}
		sealed, err := h.repo.sealOTP(a, secretBytes)
		if err != nil {
			return err
		}
		pending.Secret = sealed
		token, err := h.otp.put(pending, time.Now())
		if err != nil {
			clear(pending.Secret[:])
			return err
		}
		secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
		uri := h.otpURI(a.Login, secret)
		result.SetupToken = token
		result.Data = map[string]any{"secret": secret, "uri": uri, "expires_in": 120, "qr": otpRoute + "register/qr"}
		return nil
	case "register/finish":
		token, err := singlePostingCookie(headers, "oimo_admin_otp", 43)
		pending, ok := h.otp.take(token, binding, time.Now())
		result.ClearSetup = true
		if err != nil || !ok {
			return &adminFailure{status: 401, code: "OTP_SETUP_EXPIRED"}
		}
		defer clear(pending.Secret[:])
		if pending.Admin != a.ID || pending.Generation != a.Generation || pending.Revision != revision || len(security.OTPSealed) > 0 {
			return &adminFailure{status: 409, code: "OTP_CHANGED"}
		}
		secret, err := h.repo.openOTP(a, pending.Secret)
		if err != nil {
			return err
		}
		defer clear(secret)
		next, ok := adminauth.VerifyTOTP(secret, in.Code, 0, time.Now())
		if !ok {
			return &adminFailure{status: 401, code: "OTP_AUTHENTICATION_FAILED"}
		}
		security.OTPSealed = append(sealedOTP{}, pending.Secret...)
		security.NextStep = domain.U64(next)
	case "remove":
		wa, err := h.webAuthn()
		if err != nil {
			return err
		}
		keys, _, err := h.repo.passkeysLocked(a, wa.Config.RPID)
		if err != nil {
			return err
		}
		if err := h.repo.requireRemainingAuthenticatorLocked(a, false, len(keys.Keys)); err != nil {
			return err
		}
		if len(security.OTPSealed) == 0 {
			return &adminFailure{status: 404, code: "OTP_NOT_ENABLED"}
		}
		security.OTPSealed = []byte{}
		security.NextStep = 0
	case "policy":
		if !s.StrongReauthenticated(time.Now()) {
			return &adminFailure{status: 403, code: "STRONG_REAUTHENTICATION_REQUIRED"}
		}
		if in.PasswordDisabled && len(security.OTPSealed) == 0 {
			wa, err := h.webAuthn()
			if err != nil {
				return err
			}
			keys, _, err := h.repo.passkeysLocked(a, wa.Config.RPID)
			if err != nil {
				return err
			}
			if len(keys.Keys) == 0 {
				return &adminFailure{status: 409, code: "LAST_AUTHENTICATOR"}
			}
		}
		security.PasswordDisabled = in.PasswordDisabled
	}
	if err := h.repo.saveAdminSecurityLocked(a, security, "administrator_otp_"+strings.ReplaceAll(kind, "/", "_"), true); err != nil {
		return err
	}
	result.Logout = true
	result.Data = map[string]any{"ok": true, "redirect": "/login"}
	return nil
}

// otpURI は手動登録リンクとQRで同じ認証アプリ用URLを使う。
func (h *adminHandler) otpURI(login, secret string) string {
	issuer := "OimoBBS (" + strings.ReplaceAll(strings.TrimPrefix(strings.TrimPrefix(h.origin, "https://"), "http://"), ":", "-") + ")"
	return "otpauth://totp/" + url.PathEscape(issuer+":"+login) + "?" + url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}.Encode()
}

// otpQR は本人の登録待ちに束縛した画像だけを返し、秘密をURLや外部サービスへ渡さない。
func (h *adminHandler) otpQR(w http.ResponseWriter, r *http.Request, s adminauth.Session, binding string) {
	if !s.Reauthenticated(time.Now()) {
		h.fail(w, r, 403, "REAUTHENTICATION_REQUIRED")
		return
	}
	token, err := singlePostingCookie(r.Header, "oimo_admin_otp", 43)
	pending, ok := h.otp.peek(token, binding, time.Now())
	if err != nil || !ok {
		h.fail(w, r, 401, "OTP_SETUP_EXPIRED")
		return
	}
	defer clear(pending.Secret)
	h.repo.mu.Lock()
	a, err := h.repo.currentAdminSession(s)
	var state adminSecurityState
	var revision domain.U64
	if err == nil {
		state, revision, err = h.repo.adminSecurityLocked(a)
	}
	if err == nil && (pending.Admin != a.ID || pending.Generation != a.Generation || pending.Revision != revision || len(state.OTPSealed) > 0) {
		err = &adminFailure{status: 409, code: "OTP_CHANGED"}
	}
	var secret []byte
	if err == nil {
		secret, err = h.repo.openOTP(a, pending.Secret)
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	defer clear(secret)
	uri := h.otpURI(a.Login, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret))
	encoded, err := adminauth.EnrollmentQR(uri)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	w.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}
