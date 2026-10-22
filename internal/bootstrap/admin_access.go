// 保存先所有者のCLIから管理者を登録・権限変更し、世代増加で既存セッションを失効する。
package bootstrap

import (
	"context"
	"errors"
	"sort"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// AdministratorAccess は明示する役割・担当板・追加権限。空の担当板は全板を意味しない。
type AdministratorAccess struct {
	Role        string      `json:"role"`
	Boards      []domain.ID `json:"board_ids"`
	Permissions []string    `json:"extra_permissions"`
	Enabled     bool        `json:"enabled"`
}

// CreateAdministrator は停止中CLI専用。秘密をArgon2idで保存し、認証値を結果へ返さない。
func (r *Repository) CreateAdministrator(login, display, secret string, access AdministratorAccess) (AdministratorInfo, error) {
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
	accounts, e := r.administrators()
	if e != nil {
		return AdministratorInfo{}, e
	}
	if len(accounts) == 0 || len(accounts) >= 10000 {
		return AdministratorInfo{}, errors.New("initialize first administrator or administrator capacity exhausted")
	}
	for _, a := range accounts {
		if a.Login == login {
			return AdministratorInfo{}, errors.New("administrator login already exists")
		}
	}
	a := administrator{ID: domain.NewID(), Login: login, Display: display, Password: password, Generation: 1, Created: domain.Time(time.Now().UnixNano())}
	if e = r.setAdministratorAccess(&a, access); e != nil {
		return AdministratorInfo{}, e
	}
	return r.saveAdministratorAccess(a, "administrator_create")
}

// SetAdministratorAccess は役割・担当・有効状態を一括変更し、最後のsite_adminの失効を拒否する。
func (r *Repository) SetAdministratorAccess(login string, access AdministratorAccess) (AdministratorInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return AdministratorInfo{}, e
	}
	accounts, e := r.administrators()
	if e != nil {
		return AdministratorInfo{}, e
	}
	var selected *administrator
	activeSites := 0
	for _, a := range accounts {
		if a.Role == "site_admin" && a.Enabled {
			activeSites++
		}
		if a.Login == login {
			copy := a
			selected = &copy
		}
	}
	if selected == nil || selected.Generation == ^domain.U64(0) {
		return AdministratorInfo{}, errors.New("administrator missing or generation exhausted")
	}
	if selected.Enabled && selected.Role == "site_admin" && activeSites == 1 && (!access.Enabled || access.Role != "site_admin") {
		return AdministratorInfo{}, errors.New("cannot revoke the last active site administrator")
	}
	if e = r.setAdministratorAccess(selected, access); e != nil {
		return AdministratorInfo{}, e
	}
	selected.Generation++
	return r.saveAdministratorAccess(*selected, "administrator_access_update")
}
func (r *Repository) setAdministratorAccess(a *administrator, v AdministratorAccess) error {
	a.Role, a.Enabled = v.Role, v.Enabled
	a.Boards = append([]domain.ID{}, v.Boards...)
	a.Permissions = append([]string{}, v.Permissions...)
	sort.Slice(a.Boards, func(i, j int) bool { return a.Boards[i].String() < a.Boards[j].String() })
	sort.Strings(a.Permissions)
	if e := validateAdministratorScope(*a); e != nil {
		return e
	}
	for _, id := range a.Boards {
		if r.posting[id] == nil {
			return errors.New("administrator board scope does not exist")
		}
	}
	return nil
}
func (r *Repository) saveAdministratorAccess(a administrator, reason string) (AdministratorInfo, error) {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return AdministratorInfo{}, e
	}
	site.MinimumReader = max(site.MinimumReader, 15)
	r.stopped = true
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) { b.stopped = true; return nil, nil }); e != nil {
			return AdministratorInfo{}, e
		}
	}
	e := appendControl(r.site, reason, []store.Mutation{mutation("site", "state", site, nil), mutation("administrator", a.ID.String(), a, nil)}, []string{a.ID.String()})
	return AdministratorInfo{a.ID, a.Login, a.Generation}, e
}
