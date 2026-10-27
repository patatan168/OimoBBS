// 認証の内部エラーを固定の監査結果へ変換し、エラー本文や入力秘密を記録しない。
package bootstrap

import (
	"errors"
	"oimobbs/internal/adminauth"
)

func authenticationOutcome(err error) string {
	var limited *adminauth.Limited
	if errors.As(err, &limited) {
		return "limited"
	}
	if errors.Is(err, adminauth.ErrBusy) {
		return "busy"
	}
	return "error"
}
