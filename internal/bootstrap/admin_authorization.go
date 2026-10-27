// 管理セッションの有効性と役割・担当板を分離し、私情報権限を暗黙に付与しない。
package bootstrap

import (
	"errors"
	"oimobbs/internal/adminaccess"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"time"
)

var adminRoleRank = func() map[string]int {
	ranks := map[string]int{}
	for _, role := range adminaccess.Roles() {
		ranks[role.Value] = role.Rank
	}
	return ranks
}()
var adminExtraPermissions = func() map[string]bool {
	permissions := map[string]bool{}
	for _, p := range adminaccess.Permissions() {
		permissions[p.Value] = true
	}
	return permissions
}()

// currentAdminSession は待機後のセッション失効・期限と現在の世代を照合する。呼出元はsite mutexを保持する。
func (r *Repository) currentAdminSession(s adminauth.Session) (administrator, error) {
	a, err := r.authenticatedAdminSession(s)
	if err != nil {
		return a, err
	}
	security, _, err := r.adminSecurityLocked(a)
	if err != nil {
		return a, err
	}
	if security.PasswordChangeRequired {
		return a, &adminFailure{status: 403, code: "PASSWORD_CHANGE_REQUIRED"}
	}
	return a, nil
}

// authenticatedAdminSession はパスワード変更必須の制限セッションも含め本人と世代だけを照合する。
func (r *Repository) authenticatedAdminSession(s adminauth.Session) (administrator, error) {
	if r.adminAuth == nil || r.adminAuth.Check(s, time.Now()) != nil {
		return administrator{}, adminauth.ErrSession
	}
	return r.currentAdminAccount(s)
}

// currentAdminAccount はログイン時のパスワード照合後にアカウント変更を再検査する。
// 呼出元はsite mutexを保持し、成功後にだけセッションを発行する。
func (r *Repository) currentAdminAccount(s adminauth.Session) (administrator, error) {
	if e := r.available(); e != nil {
		return administrator{}, e
	}
	row, ok := r.site.State().Rows["administrator:"+s.Admin.String()]
	if !ok {
		return administrator{}, adminauth.ErrSession
	}
	var a administrator
	if e := strictjson.Decode(row.Value, &a); e != nil {
		return a, e
	}
	if e := validateAdministratorScope(a); e != nil {
		return a, e
	}
	if !a.Enabled || a.Generation != s.Generation {
		return a, adminauth.ErrSession
	}
	return a, nil
}

// authorizeAdmin は最低役割と担当板を存在照会の前に検査する。boardゼロはサイト範囲。
func (r *Repository) authorizeAdmin(s adminauth.Session, role string, board domain.ID) error {
	a, e := r.currentAdminSession(s)
	if e != nil {
		return e
	}
	return authorizeAdministrator(a, role, board)
}

func authorizeAdministrator(a administrator, role string, board domain.ID) error {
	minimum, ok := adminRoleRank[role]
	if !ok {
		return errors.New("unknown required administrator role")
	}
	rank, ok := adminRoleRank[a.Role]
	if !ok || rank < minimum {
		return &adminFailure{status: 403, code: "PERMISSION_DENIED"}
	}
	if a.Role == "site_admin" {
		return nil
	}
	if board == (domain.ID{}) {
		return &adminFailure{status: 403, code: "BOARD_SCOPE_REQUIRED"}
	}
	for _, id := range a.Boards {
		if id == board {
			return nil
		}
	}
	return &adminFailure{status: 403, code: "BOARD_SCOPE_DENIED"}
}
func validateAdministratorScope(a administrator) error {
	if err := adminaccess.Validate(a.Role, a.Permissions); err != nil {
		return err
	}
	if a.Boards == nil || len(a.Boards) > 128 || a.Permissions == nil || len(a.Permissions) > len(adminExtraPermissions) {
		return errors.New("invalid administrator scope")
	}
	previous := ""
	for _, id := range a.Boards {
		if id == (domain.ID{}) || id.String() <= previous {
			return errors.New("administrator boards must be a sorted set")
		}
		previous = id.String()
	}
	previous = ""
	for _, p := range a.Permissions {
		if !adminExtraPermissions[p] || p <= previous {
			return errors.New("invalid extra permission set")
		}
		previous = p
	}
	if a.Role == "site_admin" && len(a.Boards) != 0 {
		return errors.New("site administrator scope must be empty")
	}
	return nil
}
