// 管理者へ一度だけ表示する秘密の送信を、現在の認可と登録待ち状態へ束縛する。
package bootstrap

import (
	"net/http"
	"time"

	"oimobbs/internal/adminauth"
)

// checkedSecretResponse は帯域待機後と各送信片の直前に認可し、送信待ちの間は共通mutexを保持しない。
// authorize は共通mutexを保持した状態で呼ばれる。
func (h *adminHandler) checkedSecretResponse(w http.ResponseWriter, authorize func() error) http.ResponseWriter {
	return &adminCheckedWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		return authorize()
	}}
}

// checkedOTPEnrollmentResponse は手動登録用の秘密とQRを同じ未消費・未失効の登録待ちに束縛する。
func (h *adminHandler) checkedOTPEnrollmentResponse(w http.ResponseWriter, s adminauth.Session, token, binding string) http.ResponseWriter {
	return h.checkedSecretResponse(w, func() error {
		a, err := h.repo.currentAdminSession(s)
		if err != nil {
			return err
		}
		now := time.Now()
		if !s.Reauthenticated(now) {
			return &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
		}
		pending, ok := h.otp.peek(token, binding, now)
		if !ok {
			return &adminFailure{status: 401, code: "OTP_SETUP_EXPIRED"}
		}
		defer clear(pending.Secret)
		security, revision, err := h.repo.adminSecurityLocked(a)
		if err != nil {
			return err
		}
		if pending.Admin != a.ID || pending.Generation != a.Generation || pending.Revision != revision || len(security.OTPSealed) > 0 {
			return &adminFailure{status: 409, code: "OTP_CHANGED"}
		}
		return nil
	})
}
