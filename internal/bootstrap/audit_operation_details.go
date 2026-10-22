// 元の操作ログの固定コードから監査の表示分類を補う。保存済み要約・移管証明は変更しない。
package bootstrap

// auditSourceActions は旧要約が「その他」にまとめた操作の許可リスト。
// 自由記述、設定値、認証情報は表示用の索引へ転記しない。
var auditSourceActions = map[string][]string{
	"board_categories_update":           {"board.categories"},
	"administrator_password_changed":    {"administrator.password"},
	"administrator_passkey_register":    {"administrator.passkeys"},
	"administrator_passkey_remove":      {"administrator.passkeys"},
	"administrator_passkey_login":       {},
	"administrator_passkey_reauth":      {},
	"administrator_otp_register_finish": {"administrator.otp"},
	"administrator_otp_remove":          {"administrator.otp"},
	"administrator_otp_policy":          {"administrator.login_policy"},
	"administrator_otp_used":            {},
}

// rememberOperation は検証・要約保存を通過した元ログの操作種別だけを保持する。
func (index *auditIndex) rememberOperation(entry AuditEntry, action string) {
	if entry.Action != "other_admin_operation" {
		return
	}
	if _, ok := auditSourceActions[action]; !ok {
		return
	}
	if index.details == nil {
		index.details = make(map[auditIdentity]string)
	}
	index.details[auditIdentity{entry.Owner, entry.ID}] = action
}

// describeEntry は検索・表示用のコピーだけを補い、保存正本の検査値を維持する。
func (index *auditIndex) describeEntry(entry AuditEntry) AuditEntry {
	if entry.Action != "other_admin_operation" {
		return entry
	}
	if action, ok := index.details[auditIdentity{entry.Owner, entry.ID}]; ok {
		entry.Action = action
		entry.Fields = append([]string{}, auditSourceActions[action]...)
	}
	return entry
}
