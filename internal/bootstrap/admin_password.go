// 下位管理者の一時パスワード発行と変更必須状態を管理する。サイト管理者の復旧は停止中CLIだけ。
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// resetTemporaryPassword は一時秘密を保存せず一度だけ返す。再発行は旧秘密と全認証手段を失効させる。
func (r *Repository) resetTemporaryPassword(s adminauth.Session, target domain.ID, etag, key string) (string, error) {
	r.mu.Lock()
	err := r.authorizeAccountChange(s)
	var a administrator
	if err == nil {
		row, ok := r.site.State().Rows["administrator:"+target.String()]
		if !ok {
			err = &adminFailure{status: 404, code: "ACCOUNT_NOT_FOUND"}
		} else {
			err = strictjson.Decode(row.Value, &a)
		}
	}
	if err == nil && a.Role == "site_admin" {
		err = &adminFailure{status: 403, code: "SITE_ADMIN_RECOVERY_OFFLINE_ONLY"}
	}
	r.mu.Unlock()
	if err != nil {
		return "", err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	defer clear(raw)
	temporary := base64.RawURLEncoding.EncodeToString(raw)
	input := accountInput{Login: a.Login, Display: a.Display, Password: temporary, Access: AdministratorAccess{Role: a.Role, Boards: a.Boards, Permissions: a.Permissions, Enabled: a.Enabled}}
	_, err = r.changeAdminAccountMode(s, target, input, etag, key, true)
	if err != nil {
		return "", err
	}
	return temporary, nil
}

// changeOwnPassword は一時秘密を検証してから、本人の新しい秘密と制限解除・世代更新を同時保存する。
func (r *Repository) changeOwnPassword(ctx context.Context, s adminauth.Session, current, next string, now time.Time) error {
	r.mu.Lock()
	a, err := r.authenticatedAdminSession(s)
	var security adminSecurityState
	if err == nil {
		security, _, err = r.adminSecurityLocked(a)
	}
	if err == nil && a.Role == "site_admin" {
		err = &adminFailure{status: 403, code: "SITE_ADMIN_RECOVERY_OFFLINE_ONLY"}
	}
	if err == nil && !security.PasswordChangeRequired {
		err = &adminFailure{status: 403, code: "PASSWORD_CHANGE_NOT_REQUIRED"}
	}
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if current == next {
		return &adminFailure{status: 422, code: "PASSWORD_MUST_CHANGE"}
	}
	if security.PasswordChangeRequired && security.TemporaryExpires <= domain.Time(now.UnixNano()) {
		return &adminFailure{status: 401, code: "TEMPORARY_PASSWORD_EXPIRED"}
	}
	valid, err := r.adminAuth.Verify(ctx, &a.Password, current)
	if err != nil {
		return err
	}
	if !valid {
		return &adminFailure{status: 401, code: "REAUTHENTICATION_FAILED"}
	}
	password, err := r.adminAuth.DerivePassword(next)
	if err != nil {
		if errors.Is(err, adminauth.ErrPassword) {
			return &adminFailure{status: 422, code: "INVALID_PASSWORD"}
		}
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.authenticatedAdminSession(s); err != nil {
		return err
	}
	if security.TemporaryExpires <= domain.Time(time.Now().UnixNano()) {
		return &adminFailure{status: 401, code: "TEMPORARY_PASSWORD_EXPIRED"}
	}
	if a.Generation == ^domain.U64(0) {
		return ErrPostingUnavailable
	}
	a.Generation++
	a.Password = password
	security.PasswordChangeRequired = false
	security.TemporaryExpires = 0
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	site.MinimumReader = max(site.MinimumReader, adminSecurityReader)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("administrator", a.ID.String(), a, nil), mutation("admin_security", a.ID.String(), security, nil)}
	// パスワード本文を監査理由・操作結果へ含めない。保存失敗時はfail closedにする。
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	key, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return err
	}
	defer clear(key[:])
	encoded, err := json.Marshal(a)
	if err != nil {
		return err
	}
	defer clear(encoded)
	operation := domain.NewID()
	request := identity.MAC(key[:], "oimo/admin-password-change/v1", a.ID[:], encoded)
	idempotency := identity.MAC(key[:], "oimo/admin-password-key/v1", a.ID[:], operation[:])
	keyID := uint32(8)
	frame, err := controlFrame(r.site.State(), domain.NewID(), domain.Time(time.Now().UnixNano()), "administrator_password_changed", changes, []string{a.ID.String()}, domain.Actor{Kind: "admin", ID: &a.ID, Reason: "administrator_password_changed", Request: &request, Idempotency: &idempotency, KeyID: &keyID})
	if err != nil {
		return err
	}
	if result := r.site.Append(frame); result.Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN"}
	}
	return nil
}
