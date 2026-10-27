// 管理者本人のパスキーをサイトログへ保存し、公開鍵・更新履歴を検証する。
package bootstrap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type adminPasskey struct {
	Name       string              `json:"name"`
	Created    domain.Time         `json:"created_at_ns"`
	Credential webauthn.Credential `json:"credential"`
}
type adminPasskeySet struct {
	Admin domain.ID      `json:"admin_id"`
	RPID  string         `json:"rp_id"`
	Keys  []adminPasskey `json:"keys"`
}
type passkeyUser struct {
	administrator
	keys []webauthn.Credential
}

// WebAuthnID はログイン名に依存しない管理者IDを認証器へ渡す。
func (u passkeyUser) WebAuthnID() []byte { return u.ID[:] }

// WebAuthnName は認証器のアカウント表示に使うログイン名を返す。
func (u passkeyUser) WebAuthnName() string { return u.Login }

// WebAuthnDisplayName は管理者が設定した表示名を返す。
func (u passkeyUser) WebAuthnDisplayName() string { return u.Display }

// WebAuthnCredentials は当該管理者とRPに登録済みの公開鍵を返す。
func (u passkeyUser) WebAuthnCredentials() []webauthn.Credential { return u.keys }

func validateAdminPasskeys(key string, raw []byte) error {
	var v adminPasskeySet
	if len(raw) > 512<<10 || strictjson.Decode(raw, &v) != nil || v.Admin == (domain.ID{}) || key != v.Admin.String() || v.RPID == "" || v.Keys == nil || len(v.Keys) > 16 {
		return store.ErrCorrupt
	}
	seen := map[string]bool{}
	for _, k := range v.Keys {
		id := base64.RawURLEncoding.EncodeToString(k.Credential.ID)
		if !validName(k.Name) || k.Created <= 0 || len(k.Credential.ID) == 0 || len(k.Credential.ID) > 1024 || len(k.Credential.PublicKey) == 0 || seen[id] {
			return store.ErrCorrupt
		}
		seen[id] = true
	}
	return nil
}

// passkeysLocked は呼出元の所有mutex内で同じRPに登録された公開鍵だけを読み出す。
func (r *Repository) passkeysLocked(a administrator, rp string) (adminPasskeySet, domain.U64, error) {
	row, ok := r.site.State().Rows["admin_passkeys:"+a.ID.String()]
	v := adminPasskeySet{Admin: a.ID, RPID: rp, Keys: []adminPasskey{}}
	if ok {
		if err := strictjson.Decode(row.Value, &v); err != nil {
			return v, 0, err
		}
		if v.RPID != rp && len(v.Keys) != 0 {
			return v, row.Revision, errors.New("passkey relying party changed")
		}
	}
	if len(v.Keys) == 0 {
		v.RPID = rp
	}
	return v, row.Revision, nil
}
func passkeyAccount(a administrator, v adminPasskeySet) passkeyUser {
	u := passkeyUser{administrator: a}
	for _, k := range v.Keys {
		u.keys = append(u.keys, k.Credential)
	}
	return u
}

// savePasskeysLocked は認証世代と鍵一覧の版を再検査し、耐久保存の成功後だけ認証を許可する。
func (h *adminHandler) savePasskeysLocked(a administrator, revision domain.U64, v adminPasskeySet, reason string) error {
	if _, err := h.repo.currentAdminAccount(adminauth.Session{Admin: a.ID, Generation: a.Generation}); err != nil {
		return err
	}
	if h.repo.site.State().Rows["admin_passkeys:"+a.ID.String()].Revision != revision {
		return &adminFailure{status: 409, code: "PASSKEY_CHANGED"}
	}
	var site siteState
	if err := strictjson.Decode(h.repo.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	site.MinimumReader = max(site.MinimumReader, 94)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("admin_passkeys", a.ID.String(), v, nil)}
	if reason == "administrator_passkey_remove" {
		security, _, err := h.repo.adminSecurityLocked(a)
		if err != nil {
			return err
		}
		if err := h.repo.requireRemainingAuthenticatorLocked(a, len(security.OTPSealed) > 0, len(v.Keys)); err != nil {
			return err
		}

		if a.Generation == ^domain.U64(0) {
			return ErrPostingUnavailable
		}
		// 鍵削除と同じ耐久確定で全セッション・処理中の旧世代認証を失効させる。
		a.Generation++
		changes = append(changes, mutation("administrator", a.ID.String(), a, nil))
	}
	master, err := readPrivate(filepath.Join(h.repo.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return err
	}
	defer clear(secret[:])
	operation := domain.NewID()
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(encoded) > 512<<10 {
		return &adminFailure{status: 422, code: "PASSKEY_STORAGE_CAPACITY"}
	}
	if err := validateAdminPasskeys(a.ID.String(), encoded); err != nil {
		return err
	}
	request := identity.MAC(secret[:], "oimo/admin-passkey-change/v1", a.ID[:], []byte(reason), encoded)
	requestKey := identity.MAC(secret[:], "oimo/admin-passkey-key/v1", a.ID[:], operation[:])
	keyID := uint32(8)
	frame, err := controlFrame(h.repo.site.State(), domain.NewID(), domain.Time(time.Now().UnixNano()), reason, changes, []string{a.ID.String()}, domain.Actor{Kind: "admin", ID: &a.ID, Reason: reason, Request: &request, Idempotency: &requestKey, KeyID: &keyID})
	if err != nil {
		return err
	}
	if result := h.repo.site.Append(frame); result.Status != store.Durable {
		h.repo.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN"}
	}
	return nil
}
func passkeyIndex(v adminPasskeySet, id []byte) int {
	for i, k := range v.Keys {
		if bytes.Equal(k.Credential.ID, id) {
			return i
		}
	}
	return -1
}
