// ログイン画面トークンの署名・期限・再利用拒否と、接続元別の消費枠を共通化する。
package bootstrap

import (
	"errors"
	"oimobbs/internal/adminauth"
	"time"
)

func (h *adminHandler) consumeLoginForm(raw, csrf, ip string) error {
	err := h.auth.ConsumeLoginFrom(raw, csrf, ip, time.Now())
	if errors.Is(err, adminauth.ErrSession) {
		return &adminFailure{status: 403, code: "CSRF_REJECTED"}
	}
	return err
}
