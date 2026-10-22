// 未認証の開始ではアカウントを照会せず、認証器が返した本人IDと登録鍵を署名検証時に結び付ける。
package bootstrap

import (
	"bytes"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

type verifiedPasskey struct {
	Account    administrator
	Keys       adminPasskeySet
	Revision   domain.U64
	Credential *webauthn.Credential
}

// beginPasskeyLogin は存在・有効状態・鍵一覧によらない応答を返し、接続元だけで開始頻度を制限する。
func (h *adminHandler) beginPasskeyLogin(w http.ResponseWriter, r *http.Request, binding, ip string, wa *webauthn.WebAuthn) {
	csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
	if err != nil {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	if err := h.consumeLoginForm(binding, csrf, ip); err != nil {
		h.failure(w, r, err)
		return
	}
	if err := h.auth.AttemptPasskey(ip, time.Now()); err != nil {
		h.failure(w, r, err)
		return
	}
	options, session, err := wa.BeginDiscoverableLogin()
	if err != nil {
		h.fail(w, r, 400, "PASSKEY_UNAVAILABLE")
		return
	}
	token, err := h.passkeys.put(passkeyCeremony{Kind: "login", Binding: binding, Session: *session}, time.Now())
	if err != nil {
		h.failure(w, r, err)
		return
	}
	http.SetCookie(w, h.adminCookie("oimo_admin_passkey", token, 120))
	adminJSON(w, 200, options)
}

// verifyPasskey はログインで本人の保存鍵を解決し、他の操作では開始時の世代と鍵一覧の版も照合する。
func (h *adminHandler) verifyPasskey(flow passkeyCeremony, r *http.Request, wa *webauthn.WebAuthn) (v verifiedPasskey, err error) {
	if flow.Kind == "login" {
		_, v.Credential, err = wa.FinishPasskeyLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			h.repo.mu.Lock()
			defer h.repo.mu.Unlock()
			if err := h.loadPasskeyLogin(&v, rawID, userHandle, wa.Config.RPID); err != nil {
				return nil, err
			}
			return passkeyAccount(v.Account, v.Keys), nil
		}, flow.Session, r)
		return v, err
	}
	h.repo.mu.Lock()
	v.Account, err = h.repo.currentAdminAccount(adminauth.Session{Admin: flow.Account.ID, Generation: flow.Account.Generation})
	if err == nil {
		v.Keys, v.Revision, err = h.repo.passkeysLocked(v.Account, wa.Config.RPID)
	}
	h.repo.mu.Unlock()
	if err != nil {
		return v, err
	}
	if v.Revision != flow.Revision {
		return v, adminauth.ErrSession
	}
	user := passkeyAccount(v.Account, v.Keys)
	if flow.Kind == "register" {
		v.Credential, err = wa.FinishRegistration(user, flow.Session, r)
	} else {
		v.Credential, err = wa.FinishDiscoverableLogin(func(rawID, userHandle []byte) (webauthn.User, error) {
			if !bytes.Equal(userHandle, v.Account.ID[:]) || passkeyIndex(v.Keys, rawID) < 0 {
				return nil, adminauth.ErrSession
			}
			return user, nil
		}, flow.Session, r)
	}
	return v, err
}

// loadPasskeyLogin は認証器の本人IDと鍵IDが同一の有効管理者を示す場合だけ鍵を返す。所有mutex内で呼ぶ。
func (h *adminHandler) loadPasskeyLogin(v *verifiedPasskey, rawID, userHandle []byte, rp string) error {
	if len(userHandle) != len(domain.ID{}) {
		return adminauth.ErrSession
	}
	var id domain.ID
	copy(id[:], userHandle)
	row, ok := h.repo.site.State().Rows["administrator:"+id.String()]
	if !ok || strictjson.Decode(row.Value, &v.Account) != nil || !bytes.Equal(v.Account.ID[:], userHandle) {
		return adminauth.ErrSession
	}
	a, err := h.repo.currentAdminAccount(adminauth.Session{Admin: id, Generation: v.Account.Generation})
	if err != nil {
		return err
	}
	v.Account = a
	v.Keys, v.Revision, err = h.repo.passkeysLocked(a, rp)
	if err != nil {
		return err
	}
	if passkeyIndex(v.Keys, rawID) < 0 {
		return adminauth.ErrSession
	}
	return nil
}
