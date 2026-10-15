// 管理者の役割・担当板・追加権限と、サイト名変更receiptの保存形式を検証する。
package bootstrap

import (
	"errors"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"regexp"
)

var adminLoginName = regexp.MustCompile(`^[a-z0-9_.-]{3,64}$`)
var adminRequestKey = regexp.MustCompile(`^[A-Za-z0-9_.-]{16,64}$`)

type administrator struct {
	ID          domain.ID          `json:"id"`
	Login       string             `json:"login_name"`
	Display     string             `json:"display_name"`
	Password    adminauth.Password `json:"password"`
	Role        string             `json:"role"`
	Boards      []domain.ID        `json:"board_ids"`
	Permissions []string           `json:"extra_permissions"`
	Enabled     bool               `json:"enabled"`
	Generation  domain.U64         `json:"auth_generation"`
	Created     domain.Time        `json:"created_at_ns"`
}
type adminReceipt struct {
	ID       domain.ID   `json:"id"`
	Admin    domain.ID   `json:"admin_id"`
	Key      domain.Hash `json:"request_key_hmac"`
	Request  domain.Hash `json:"request_hmac"`
	Name     string      `json:"name"`
	Revision domain.U64  `json:"revision"`
	Created  domain.Time `json:"created_at_ns"`
	Expires  domain.Time `json:"expires_at_ns"`
}

func validateAdministrator(key string, old, next []byte) error {
	var a administrator
	if e := strictjson.Decode(next, &a); e != nil {
		return e
	}
	if a.ID == (domain.ID{}) || key != a.ID.String() || !adminLoginName.MatchString(a.Login) || !validName(a.Display) || a.Generation == 0 || a.Created <= 0 {
		return errors.New("invalid administrator")
	}
	if e := validateAdministratorScope(a); e != nil {
		return e
	}
	if e := a.Password.Validate(); e != nil {
		return e
	}
	if len(old) > 0 {
		var p administrator
		if e := strictjson.Decode(old, &p); e != nil {
			return e
		}
		if a.ID != p.ID || a.Login != p.Login || a.Created != p.Created || p.Generation == ^domain.U64(0) || a.Generation != p.Generation+1 {
			return errors.New("administrator generation mismatch")
		}
	}
	return nil
}
func validateAdminReceipt(key string, old, next []byte) error {
	if isNetworkReceipt(next) {
		return validateNetworkReceipt(key, old, next)
	}
	if isCapReceipt(next) {
		return validateCapReceipt(key, old, next)
	}
	if isAnonymousReceipt(next) {
		return validateAnonymousReceipt(key, old, next)
	}
	if isAccountReceipt(next) {
		return validateAccountReceipt(key, old, next)
	}
	var v adminReceipt
	if e := strictjson.Decode(next, &v); e != nil {
		return e
	}
	if key != v.Key.String() || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || !validName(v.Name) || v.Revision == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 {
		return errors.New("invalid administrator receipt")
	}
	if len(old) > 0 {
		var p adminReceipt
		if e := strictjson.Decode(old, &p); e != nil {
			return e
		}
		if p.Expires > v.Created {
			return errors.New("administrator receipt still active")
		}
	}
	return nil
}
