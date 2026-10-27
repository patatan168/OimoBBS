// 稼働中の管理者変更。再認証・世代・CAS・固定要求receiptを一括Syncへ結び付ける。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"oimobbs/internal/adminaccess"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// AdminAccount は認証値を除いた管理者の設定。権限を検査した管理経路だけへ渡す。
type AdminAccount struct {
	ID         domain.ID           `json:"id"`
	Login      string              `json:"login_name"`
	Display    string              `json:"display_name"`
	Access     AdministratorAccess `json:"access"`
	Generation domain.U64          `json:"auth_generation"`
	Revision   domain.U64          `json:"revision"`
}

// ETag はアカウント行の版を含み、他のアカウントの版との取り違えを防ぐ。
func (a AdminAccount) ETag() string {
	return fmt.Sprintf(`"administrator-%s-%d"`, a.ID.String(), a.Revision)
}
func accountView(a administrator, revision domain.U64) AdminAccount {
	return AdminAccount{a.ID, a.Login, a.Display, AdministratorAccess{a.Role, append([]domain.ID{}, a.Boards...), append([]string{}, adminaccess.Effective(a.Role, a.Permissions)...), a.Enabled}, a.Generation, revision}
}

type accountInput struct {
	Login    string              `json:"login_name"`
	Display  string              `json:"display_name"`
	Password string              `json:"password"`
	Access   AdministratorAccess `json:"access"`
}
type accountReceipt struct {
	Type    string       `json:"type"`
	ID      domain.ID    `json:"id"`
	Admin   domain.ID    `json:"admin_id"`
	Key     domain.Hash  `json:"request_key_hmac"`
	Request domain.Hash  `json:"request_hmac"`
	Account AdminAccount `json:"account"`
	Created domain.Time  `json:"created_at_ns"`
	Expires domain.Time  `json:"expires_at_ns"`
}

func isAccountReceipt(raw []byte) bool {
	var header struct {
		Type string `json:"type"`
	}
	return json.Unmarshal(raw, &header) == nil && header.Type == "administrator_change"
}

// validateAccountReceipt は秘密を持たない確定結果と24時間の再送期限を検査する。
func validateAccountReceipt(key string, old, next []byte) error {
	var v accountReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	a := v.Account
	if v.Type != "administrator_change" || key != v.Key.String() || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 || a.ID == (domain.ID{}) || a.Generation == 0 || a.Revision == 0 || !adminLoginName.MatchString(a.Login) || !validName(a.Display) {
		return store.ErrCorrupt
	}
	if e := validateAdministratorScope(administrator{Role: a.Access.Role, Boards: a.Access.Boards, Permissions: a.Access.Permissions, Enabled: a.Access.Enabled}); e != nil {
		return e
	}
	if len(old) > 0 {
		var p accountReceipt
		if strictjson.Decode(old, &p) != nil || p.Expires > v.Created {
			return store.ErrCorrupt
		}
	}
	return nil
}

// adminAccounts は再認証済みsite_adminだけへ秘密を除いた固定一覧を返す。
func (r *Repository) adminAccounts(s adminauth.Session) ([]AdminAccount, domain.U64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.authorizeAccountChange(s); e != nil {
		return nil, 0, e
	}
	accounts, e := r.administrators()
	if e != nil {
		return nil, 0, e
	}
	out := make([]AdminAccount, 0, len(accounts))
	state := r.site.State()
	for _, a := range accounts {
		out = append(out, accountView(a, state.Rows["administrator:"+a.ID.String()].Revision))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Login < out[j].Login })
	return out, state.Seq, nil
}
func (r *Repository) authorizeAccountChange(s adminauth.Session) error {
	if e := r.currentAdministrator(s); e != nil {
		return e
	}
	if !s.Reauthenticated(time.Now()) {
		return &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	return nil
}

// changeAdminAccount は入力秘密のHMACを要求照合に使い、導出後にも現在の権限・版を再検査する。
// 新規のIf-Matchは一覧GETのsite制御版、更新のIf-Matchは対象アカウント版。
func (r *Repository) changeAdminAccount(s adminauth.Session, target domain.ID, input accountInput, etag, key string) (AdminAccount, error) {
	return r.changeAdminAccountMode(s, target, input, etag, key, false)
}

// changeAdminAccountMode は一時パスワード発行だけを既存のWeb認証情報リセットとして許可する。
func (r *Repository) changeAdminAccountMode(s adminauth.Session, target domain.ID, input accountInput, etag, key string, temporary bool) (AdminAccount, error) {
	r.mu.Lock()
	e := r.authorizeAccountChange(s)
	manager := r.adminAuth
	r.mu.Unlock()
	if e != nil {
		return AdminAccount{}, e
	}
	if !adminRequestKey.MatchString(key) {
		return AdminAccount{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminAccount{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	if !validName(input.Display) || !adminLoginName.MatchString(input.Login) || len(input.Password) > 512 || target == (domain.ID{}) && input.Password == "" {
		return AdminAccount{}, &adminFailure{status: 422, code: "INVALID_ACCOUNT"}
	}
	if err := adminaccess.Validate(input.Access.Role, input.Access.Permissions); err != nil {
		return AdminAccount{}, &adminFailure{status: 422, code: "INVALID_ACCESS"}
	}
	sort.Slice(input.Access.Boards, func(i, j int) bool { return input.Access.Boards[i].String() < input.Access.Boards[j].String() })
	sort.Strings(input.Access.Permissions)
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return AdminAccount{}, e
	}
	defer clear(master)
	secret, e := identity.DeriveKey(master, "dedup", 8)
	if e != nil {
		return AdminAccount{}, e
	}
	defer clear(secret[:])
	raw, e := json.Marshal(input)
	if e != nil {
		return AdminAccount{}, e
	}
	defer clear(raw)
	requestKey := identity.MAC(secret[:], "oimo/admin-account-key/v1", s.Admin[:], []byte(key))
	request := identity.MAC(secret[:], "oimo/admin-account-change/v1", s.Admin[:], target[:], []byte(etag), raw)
	// 成功済み再送は、新しいsaltの導出より先に元の確定結果を返す。
	r.mu.Lock()
	if e = r.authorizeAccountChange(s); e != nil {
		r.mu.Unlock()
		return AdminAccount{}, e
	}
	if v, ok, e := r.accountReplay(requestKey, request); ok || e != nil {
		r.mu.Unlock()
		return v, e
	}
	r.mu.Unlock()
	var password *adminauth.Password
	if input.Password != "" {
		// Argon2idは認証と同じ有限workerで検証枠を共有し、新規登録を無制限に並列化しない。
		// 保存用saltの生成は下の専用導出枠で行う。
		if manager == nil {
			return AdminAccount{}, adminauth.ErrSession
		}
		p, e := manager.DerivePassword(input.Password)
		if e != nil {
			if e == adminauth.ErrPassword {
				return AdminAccount{}, &adminFailure{status: 422, code: "INVALID_PASSWORD"}
			}
			return AdminAccount{}, e
		}
		password = &p
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.authorizeAccountChange(s); e != nil {
		return AdminAccount{}, e
	}
	if v, ok, e := r.accountReplay(requestKey, request); ok || e != nil {
		return v, e
	}
	state := r.site.State()
	var site siteState
	if e = strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		return AdminAccount{}, e
	}
	accounts, e := r.administrators()
	if e != nil {
		return AdminAccount{}, e
	}
	a := administrator{}
	active := 0
	for _, v := range accounts {
		if v.Enabled && v.Role == "site_admin" {
			active++
		}
		if v.ID == target {
			a = v
		}
		if target == (domain.ID{}) && v.Login == input.Login {
			return AdminAccount{}, &adminFailure{status: 409, code: "LOGIN_CONFLICT"}
		}
	}
	now := domain.Time(time.Now().UnixNano())
	if target == (domain.ID{}) {
		if etag != accountListETag(state.Seq) {
			return AdminAccount{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		if len(accounts) >= 10000 {
			return AdminAccount{}, &adminFailure{status: 503, code: "ACCOUNT_CAPACITY"}
		}
		a = administrator{ID: domain.NewID(), Login: input.Login, Generation: 1, Created: now}
	} else {
		if a.ID == (domain.ID{}) {
			return AdminAccount{}, &adminFailure{status: 404, code: "ACCOUNT_NOT_FOUND"}
		}
		if etag != accountView(a, state.Rows["administrator:"+a.ID.String()].Revision).ETag() {
			return AdminAccount{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		if a.Login != input.Login {
			return AdminAccount{}, &adminFailure{status: 422, code: "LOGIN_IMMUTABLE"}
		}
		if a.Enabled && a.Role == "site_admin" && active == 1 && (!input.Access.Enabled || input.Access.Role != "site_admin") {
			return AdminAccount{}, &adminFailure{status: 409, code: "LAST_SITE_ADMIN"}
		}
		if a.Generation == ^domain.U64(0) {
			return AdminAccount{}, ErrPostingUnavailable
		}
		a.Generation++
	}
	a.Display = input.Display
	if target != (domain.ID{}) && a.Role == "site_admin" && (password != nil || input.Access.Role != "site_admin") {
		return AdminAccount{}, &adminFailure{status: 403, code: "SITE_ADMIN_RECOVERY_OFFLINE_ONLY"}
	}
	if target != (domain.ID{}) && password != nil && !temporary {
		return AdminAccount{}, &adminFailure{status: 403, code: "TEMPORARY_PASSWORD_REQUIRED"}
	}
	if password != nil {
		a.Password = *password
	}
	if e = r.setAdministratorAccess(&a, input.Access); e != nil {
		return AdminAccount{}, &adminFailure{status: 422, code: "INVALID_ACCESS"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 || state.Seq == ^domain.U64(0) || now > domain.Time(1<<63-1)-86400e9 {
		return AdminAccount{}, ErrPostingUnavailable
	}
	seq := state.Seq + 1
	id := domain.NewID()
	view := accountView(a, seq)
	receipt := accountReceipt{"administrator_change", id, s.Admin, requestKey, request, view, now, now + 86400e9}
	site.MinimumReader = max(site.MinimumReader, 17)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("administrator", a.ID.String(), a, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	if row, ok := state.Rows["admin_passkeys:"+a.ID.String()]; password != nil && ok {
		var keys adminPasskeySet
		if e := strictjson.Decode(row.Value, &keys); e != nil {
			return AdminAccount{}, e
		}
		keys.Keys = []adminPasskey{}
		changes = append(changes, mutation("admin_passkeys", a.ID.String(), keys, nil))
	}
	if temporary {
		site.MinimumReader = max(site.MinimumReader, adminSecurityReader)
		changes[0] = mutation("site", "state", site, nil)
		security := adminSecurityState{Admin: a.ID, OTPSealed: []byte{}, PasswordChangeRequired: true, TemporaryExpires: domain.Time(time.Now().Add(time.Hour).UnixNano())}
		changes = append(changes, mutation("admin_security", a.ID.String(), security, nil))
	}
	for i := range changes {
		changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
	}
	reason := "administrator_update"
	if target == (domain.ID{}) {
		reason = "administrator_create"
	}
	keyID := uint32(8)
	op := store.ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &s.Admin, Reason: reason, Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: "administrator_saved", Targets: []string{a.ID.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
	encoded, e := json.Marshal(op)
	if e != nil {
		return AdminAccount{}, e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(seq), Records: []store.Record{{ID: id, JSON: encoded}}})
	if e != nil {
		return AdminAccount{}, e
	}
	result := r.site.Append(frame)
	if result.Status != store.Durable {
		r.stopped = true
		return AdminAccount{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	return view, nil
}
func accountListETag(seq domain.U64) string { return fmt.Sprintf(`"administrators-%d"`, seq) }
func (r *Repository) accountReplay(key, request domain.Hash) (AdminAccount, bool, error) {
	row, ok := r.site.State().Rows["admin_receipt:"+key.String()]
	if !ok {
		return AdminAccount{}, false, nil
	}
	var v accountReceipt
	if e := strictjson.Decode(row.Value, &v); e != nil {
		return AdminAccount{}, true, e
	}
	now := domain.Time(time.Now().UnixNano())
	if v.Created > now {
		return AdminAccount{}, true, ErrPostingUnavailable
	}
	if now >= v.Expires {
		return AdminAccount{}, false, nil
	}
	if v.Request != request {
		return AdminAccount{}, true, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
	}
	return v.Account, true, nil
}
