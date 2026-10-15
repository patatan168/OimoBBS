// 管理者初期化と認証済みサイト名変更を、サイト所有mutexとcontrol WALへ接続する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

// AdministratorInfo はCLIへ返す公開可能な管理アカウント情報。認証秘密・私情報権限を含めない。
type AdministratorInfo struct {
	ID         domain.ID  `json:"id"`
	Login      string     `json:"login_name"`
	Generation domain.U64 `json:"auth_generation"`
}

func (r *Repository) administrators() ([]administrator, error) {
	out := []administrator{}
	seen := map[string]bool{}
	for k, row := range r.site.State().Rows {
		if !strings.HasPrefix(k, "administrator:") {
			continue
		}
		var a administrator
		if e := strictjson.Decode(row.Value, &a); e != nil {
			return nil, e
		}
		if seen[a.Login] {
			return nil, errors.New("duplicate administrator login")
		}
		seen[a.Login] = true
		out = append(out, a)
	}
	return out, nil
}

// ConfigureAdministrator は停止中の所有者CLI専用。初回登録または同じアカウントの秘密更新を行う。
func (r *Repository) ConfigureAdministrator(login, display, secret string, reset bool) (AdministratorInfo, error) {
	if !adminLoginName.MatchString(login) || !validName(display) {
		return AdministratorInfo{}, errors.New("invalid administrator name")
	}
	password, e := adminauth.NewPassword(secret)
	if e != nil {
		return AdministratorInfo{}, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.available(); e != nil {
		return AdministratorInfo{}, e
	}
	admins, e := r.administrators()
	if e != nil {
		return AdministratorInfo{}, e
	}
	a := administrator{ID: domain.NewID(), Login: login, Display: display, Password: password, Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true, Generation: 1, Created: domain.Time(time.Now().UnixNano())}
	if reset {
		found := false
		for _, old := range admins {
			if old.Login == login {
				a = old
				found = true
				break
			}
		}
		if !found || a.Generation == ^domain.U64(0) {
			return AdministratorInfo{}, errors.New("administrator not found or generation exhausted")
		}
		a.Password = password
		a.Generation++
	} else if len(admins) != 0 {
		return AdministratorInfo{}, errors.New("initial administrator already configured")
	}
	r.stopped = true
	for _, b := range r.posting {
		if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.stopped = true; return nil, nil }); e != nil {
			return AdministratorInfo{}, e
		}
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return AdministratorInfo{}, e
	}
	site.MinimumReader = max(site.MinimumReader, 6)
	reason := "administrator_bootstrap"
	if reset {
		reason = "administrator_password_reset"
	}
	e = appendControl(r.site, reason, []store.Mutation{mutation("site", "state", site, nil), mutation("administrator", a.ID.String(), a, nil)}, []string{a.ID.String()})
	return AdministratorInfo{a.ID, a.Login, a.Generation}, e
}
func (r *Repository) currentAdministrator(s adminauth.Session) error {
	return r.authorizeAdmin(s, "site_admin", domain.ID{})
}

// AdminSite はサイト設定の管理用DTO。保存済み秘密や投稿情報は持たない。
type AdminSite struct {
	ID       domain.ID  `json:"id"`
	Name     string     `json:"name"`
	Revision domain.U64 `json:"revision"`
}

func (s AdminSite) ETag() string { return fmt.Sprintf(`"%s:%d"`, s.ID, s.Revision) }
func (r *Repository) adminSite(session adminauth.Session) (AdminSite, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.currentAdministrator(session); e != nil {
		return AdminSite{}, e
	}
	row := r.site.State().Rows["site:state"]
	var site siteState
	e := strictjson.Decode(row.Value, &site)
	return AdminSite{site.ID, site.Name, row.Revision}, e
}

type adminFailure struct {
	status    int
	code      string
	operation domain.ID
}

func (e *adminFailure) Error() string { return e.code }

// updateAdminSite はreceipt照会→CAS→操作者付き一括Syncの順。応答前に私情報なしの操作証跡を残す。
func (r *Repository) updateAdminSite(session adminauth.Session, name, etag, key string) (AdminSite, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.currentAdministrator(session); e != nil {
		return AdminSite{}, e
	}
	if !adminRequestKey.MatchString(key) {
		return AdminSite{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminSite{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	if !validName(name) {
		return AdminSite{}, &adminFailure{status: 422, code: "INVALID_NAME"}
	}
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return AdminSite{}, e
	}
	defer clear(master)
	secret, e := identity.DeriveKey(master, "dedup", 8)
	if e != nil {
		return AdminSite{}, e
	}
	requestKey := identity.MAC(secret[:], "oimo/admin-key/v1", session.Admin[:], []byte(key))
	request := identity.MAC(secret[:], "oimo/admin-site/v1", session.Admin[:], []byte(name), []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	var site siteState
	row := state.Rows["site:state"]
	if e = strictjson.Decode(row.Value, &site); e != nil {
		return AdminSite{}, e
	}
	if prior, ok := state.Rows["admin_receipt:"+requestKey.String()]; ok {
		var receipt adminReceipt
		if e = strictjson.Decode(prior.Value, &receipt); e != nil {
			return AdminSite{}, e
		}
		if receipt.Created > now {
			return AdminSite{}, ErrPostingUnavailable
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminSite{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return AdminSite{site.ID, receipt.Name, receipt.Revision}, nil
		}
	}
	current := AdminSite{site.ID, site.Name, row.Revision}
	if etag != current.ETag() {
		return AdminSite{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "admin_receipt:") {
			count++
		}
	}
	if count >= 200000 {
		return AdminSite{}, ErrPostingUnavailable
	}
	if state.Seq == ^domain.U64(0) {
		return AdminSite{}, ErrPostingUnavailable
	}
	id := domain.NewID()
	seq := state.Seq + 1
	site.Name = name
	site.PublicRevision = seq
	receipt := adminReceipt{ID: id, Admin: session.Admin, Key: requestKey, Request: request, Name: name, Revision: seq, Created: now, Expires: now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("admin_receipt", requestKey.String(), receipt, nil)}
	for i := range changes {
		changes[i].ExpectedRevision = state.Rows[changes[i].Collection+":"+changes[i].Key].Revision
	}
	keyID := uint32(8)
	op := store.ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "admin", ID: &session.Admin, Reason: "site_name_update", Request: &request, Idempotency: &requestKey, KeyID: &keyID}, Mutations: changes, Result: store.ControlResult{Code: "site_updated", Targets: []string{site.ID.String()}, RequestKey: &requestKey, Request: &request, KeyID: &keyID, Expires: &receipt.Expires}}
	raw, e := json.Marshal(op)
	if e != nil {
		return AdminSite{}, e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: uint64(seq), Records: []store.Record{{ID: id, JSON: raw}}})
	if e != nil {
		return AdminSite{}, e
	}
	result := r.site.Append(frame)
	if result.Status != store.Durable {
		r.stopped = true
		return AdminSite{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	r.publicRevision.Store(uint64(site.PublicRevision))
	return AdminSite{site.ID, name, seq}, nil
}
