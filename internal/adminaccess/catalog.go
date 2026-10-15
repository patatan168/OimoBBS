// Package adminaccess は管理者ロールと非公開情報の許可を、認可・保存・画面で共通定義する。
package adminaccess

import (
	"errors"
	"slices"
)

// Role は管理操作の大まかな範囲。Rankが高いロールは下位の操作も行える。
type Role struct {
	Value, Label, Description string
	Rank                      int
}

// Permission はロールだけでは付かない非公開情報の許可と、最低ロール。
type Permission struct {
	Value, Label, Description, MinimumRole string
}

var roles = []Role{
	{"moderator", "投稿・スレッドの管理担当", "担当板の投稿削除・スレッドの公開停止・投稿停止・自動通報の確認を行います。板設定・スレッド一覧・操作記録は閲覧できません。", 2},
	{"board_admin", "板管理者", "投稿管理と全追加権限に加えて、担当板の設定・規制・ローカルルール・スレッド設定・アーカイブ・CAP（名前付きの投稿資格）を管理します。", 3},
	{"site_admin", "サイト管理者", "全板の操作と全追加権限に加えて、サイト設定・板の追加・管理者への権限付与・運用設定を管理します。", 4},
}

var permissions = []Permission{
	{"private_reports.read", "削除依頼の閲覧・回答", "非公開の削除依頼・照会の本文と連絡先を閲覧し、回答します。", "moderator"},
	{"evidence.manage", "記録の閲覧・保全・出力", "投稿原本・接続元IPなどの照会、案件用コピーの保存・期限延長・解除、提出用ファイルの出力・ダウンロード、受け渡し履歴の登録をまとめて許可します。履歴の登録だけで相手へファイルが送信されることはありません。", "moderator"},
}

// IncludesExtras は全追加権限をロールに含むか返す。
func IncludesExtras(role string) bool { return role == "board_admin" || role == "site_admin" }

// Granted は実在する権限について、ロールに含まれる許可と明示許可を照合する。
func Granted(role string, granted []string, permission string) bool {
	p, ok := LookupPermission(permission)
	if !ok {
		return false
	}
	rank, valid := Rank(role)
	return valid && rank >= p.MinimumRank() && (IncludesExtras(role) || slices.Contains(granted, permission))
}

// Effective は画面・APIで表示する実効権限を返す。保存値を変更しない。
func Effective(role string, granted []string) []string {
	if !IncludesExtras(role) {
		return slices.Clone(granted)
	}
	values := []string{}
	for _, p := range permissions {
		values = append(values, p.Value)
	}
	slices.Sort(values)
	return values
}

// Roles は有効なロールを低い権限から返す。返した一覧の変更は定義へ影響しない。
func Roles() []Role { return slices.Clone(roles) }

// Permissions は実際に機能する非公開情報の許可だけを表示順で返す。
func Permissions() []Permission { return slices.Clone(permissions) }

// Rank は有効なロールの順位を返し、廃止済み・未知のロールは拒否する。
func Rank(value string) (int, bool) {
	for _, role := range roles {
		if role.Value == value {
			return role.Rank, true
		}
	}
	return 0, false
}

// RoleLabel は条件説明に使うロール名を返す。未知の値は空文字になる。
func RoleLabel(value string) string {
	for _, role := range roles {
		if role.Value == value {
			return role.Label
		}
	}
	return ""
}

// Validate は廃止済みロール・許可と、ロール不足を拒否する。
// 並び順・重複・担当板の検査は保存側の責務。
func Validate(role string, granted []string) error {
	rank, ok := Rank(role)
	if !ok {
		return errors.New("有効なロールを選択してください。")
	}
	for _, value := range granted {
		p, ok := LookupPermission(value)
		if !ok {
			return errors.New("廃止済み、または存在しない追加権限です。")
		}
		minimum, _ := Rank(p.MinimumRole)
		if rank < minimum {
			return errors.New(p.Label + "には「" + RoleLabel(p.MinimumRole) + "」以上のロールが必要です。")
		}

	}
	return nil
}

// LookupPermission は認可と画面補助に使う、現在有効な許可の定義を返す。
func LookupPermission(value string) (Permission, bool) {
	for _, p := range permissions {
		if p.Value == value {
			return p, true
		}
	}
	return Permission{}, false
}

// Conditions は追加権限の個別付与とロールによる自動許可を説明する。
func (p Permission) Conditions() string {
	return "投稿・スレッドの管理担当には個別に付与。板管理者・サイト管理者にはロールとして含まれます。担当板の範囲内で利用できます。"
}

// MinimumRank はフォーム補助へ最低ロールの順位だけを渡す。認可はサーバーで別途行う。
func (p Permission) MinimumRank() int { rank, _ := Rank(p.MinimumRole); return rank }
