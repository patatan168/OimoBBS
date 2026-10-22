// 管理者ごとの認証方針・暗号化OTP鍵・使用済み時刻を同じ耐久ログで管理する。
package bootstrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const adminSecurityReader = 95

// 二要素認証を保存した後は、OTP単独ログインを許していた旧実行物へ戻さない。
const adminTwoFactorReader = 96

// sealedOTP はJSONで正規base64を使う暗号文。厳密JSON検査にも配列表現と混同させない。
type sealedOTP []byte

func (v *sealedOTP) UnmarshalJSON(raw []byte) error {
	var encoded string
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &encoded) != nil {
		return store.ErrCorrupt
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != 0 && len(decoded) != 48 || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return store.ErrCorrupt
	}
	*v = decoded
	return nil
}

type adminSecurityState struct {
	PasswordChangeRequired bool        `json:"password_change_required"`
	TemporaryExpires       domain.Time `json:"temporary_expires_at_ns"`
	Admin                  domain.ID   `json:"admin_id"`
	PasswordDisabled       bool        `json:"password_disabled"`
	OTPSealed              sealedOTP   `json:"otp_sealed"`
	NextStep               domain.U64  `json:"otp_next_step"`
}

func validateAdminSecurity(key string, old, raw []byte) error {
	var v adminSecurityState
	if len(raw) > 1024 || strictjson.Decode(raw, &v) != nil || v.Admin == (domain.ID{}) || key != v.Admin.String() || v.OTPSealed == nil || len(v.OTPSealed) != 0 && len(v.OTPSealed) != 48 || len(v.OTPSealed) == 0 && v.NextStep != 0 {
		return store.ErrCorrupt
	}
	if v.PasswordChangeRequired && (v.PasswordDisabled || len(v.OTPSealed) > 0 || v.TemporaryExpires <= 0) || !v.PasswordChangeRequired && v.TemporaryExpires != 0 {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var prior adminSecurityState
		if strictjson.Decode(old, &prior) != nil || prior.Admin != v.Admin || len(v.OTPSealed) > 0 && bytes.Equal(prior.OTPSealed, v.OTPSealed) && v.NextStep < prior.NextStep {
			return store.ErrCorrupt
		}
	}
	return nil
}

// adminSecurityLocked は未設定の管理者を従来のパスワード許可状態として扱う。所有mutex内で呼ぶ。
func (r *Repository) adminSecurityLocked(a administrator) (adminSecurityState, domain.U64, error) {
	v := adminSecurityState{Admin: a.ID, OTPSealed: []byte{}}
	row, ok := r.site.State().Rows["admin_security:"+a.ID.String()]
	if !ok {
		return v, 0, nil
	}
	err := strictjson.Decode(row.Value, &v)
	return v, row.Revision, err
}

// otpCipher はサイトmasterから専用鍵を導出する。nonce生成は標準AES-GCMへ委ねる。
func (r *Repository) otpCipher(a administrator) (cipher.AEAD, []byte, error) {
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(master)
	key, err := identity.DeriveKey(master, "admin_totp", 1)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key[:])
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCMWithRandomNonce(block)
	var site siteState
	if err == nil {
		err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site)
	}
	aad := []byte("oimo/admin-totp/v1:" + site.ID.String() + ":" + a.ID.String())
	return gcm, aad, err
}

// sealOTP はサイトと管理者へ暗号文を束縛し、ログへ平文の共有鍵を残さない。
func (r *Repository) sealOTP(a administrator, secret []byte) ([]byte, error) {
	gcm, aad, err := r.otpCipher(a)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nil, secret, aad), nil
}
func (r *Repository) openOTP(a administrator, sealed []byte) ([]byte, error) {
	gcm, aad, err := r.otpCipher(a)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nil, sealed, aad)
}

// saveAdminSecurityLocked は消費済み区間・認証方針を確定する。revoke時は同じ保存で全セッションを失効させる。
func (r *Repository) saveAdminSecurityLocked(a administrator, v adminSecurityState, reason string, revoke bool) error {
	if _, err := r.currentAdminAccount(adminauth.Session{Admin: a.ID, Generation: a.Generation}); err != nil {
		return err
	}
	encoded, err := json.Marshal(v)
	if err != nil {
		return err
	}
	old := r.site.State().Rows["admin_security:"+a.ID.String()].Value
	if err := validateAdminSecurity(a.ID.String(), old, encoded); err != nil {
		return err
	}
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	site.MinimumReader = max(site.MinimumReader, adminTwoFactorReader)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("admin_security", a.ID.String(), v, nil)}
	if revoke {
		if a.Generation == ^domain.U64(0) {
			return ErrPostingUnavailable
		}
		a.Generation++
		changes = append(changes, mutation("administrator", a.ID.String(), a, nil))
	}
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
	operation := domain.NewID()
	request := identity.MAC(key[:], "oimo/admin-security/v1", a.ID[:], []byte(reason), encoded)
	idempotency := identity.MAC(key[:], "oimo/admin-security-key/v1", a.ID[:], operation[:])
	keyID := uint32(8)
	frame, err := controlFrame(r.site.State(), operation, domain.Time(time.Now().UnixNano()), reason, changes, []string{a.ID.String()}, domain.Actor{Kind: "admin", ID: &a.ID, Reason: reason, Request: &request, Idempotency: &idempotency, KeyID: &keyID})
	if err != nil {
		return err
	}
	if result := r.site.Append(frame); result.Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN"}
	}
	return nil
}

// requireRemainingAuthenticatorLocked はパスワード禁止時に最後の認証手段を削除させない。
func (r *Repository) requireRemainingAuthenticatorLocked(a administrator, otp bool, passkeys int) error {
	security, _, err := r.adminSecurityLocked(a)
	if err != nil {
		return err
	}
	if security.PasswordDisabled && !otp && passkeys == 0 {
		return &adminFailure{status: 409, code: "LAST_AUTHENTICATOR"}
	}
	return nil
}
