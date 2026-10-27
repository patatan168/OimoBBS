// 管理者の現在の担当だけからキャップ一覧とそのCAS版を決め、担当外の件数を公開しない。
package bootstrap

import (
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"time"
)

type capScope struct {
	site   bool
	boards map[domain.ID]bool
}

// currentCapAdministrator はsite mutexの下で世代・役割・再認証を一度照合する。
func (r *Repository) currentCapAdministrator(s adminauth.Session) (administrator, error) {
	a, e := r.currentAdminSession(s)
	if e != nil {
		return a, e
	}
	if adminRoleRank[a.Role] < 3 {
		return a, &adminFailure{status: 403, code: "PERMISSION_DENIED"}
	}
	if !s.Reauthenticated(time.Now()) {
		return a, &adminFailure{status: 403, code: "REAUTHENTICATION_REQUIRED"}
	}
	return a, nil
}

// authorizeCap はHTTP境界でも同じ現在世代・担当検査を適用する。呼出元はsite mutexを保持する。
func (r *Repository) authorizeCap(s adminauth.Session, boards []domain.ID) error {
	a, e := r.currentCapAdministrator(s)
	if e != nil {
		return e
	}
	if !newCapScope(a).allows(boards) {
		return &adminFailure{status: 403, code: "BOARD_SCOPE_DENIED"}
	}
	return nil
}
func newCapScope(a administrator) capScope {
	scope := capScope{site: a.Role == "site_admin", boards: map[domain.ID]bool{}}
	for _, id := range a.Boards {
		scope.boards[id] = true
	}
	return scope
}
func (s capScope) allows(boards []domain.ID) bool {
	if s.site {
		return true
	}
	for _, id := range boards {
		if !s.boards[id] {
			return false
		}
	}
	return true
}

// scopedCapRevision は閲覧可能な資格だけの発行・停止を数える。担当外変更とCookie発行で増えない。
func scopedCapRevision(scope capScope, reg *capRegistry) domain.U64 {
	var revision domain.U64
	for _, v := range reg.Records {
		if scope.allows(v.Boards) {
			revision += v.Revision
		}
	}
	return revision
}
