// 設定値を利用者が意味で選べる日本語の選択肢と説明へ変換する。
package webui

import (
	"html/template"
	"oimobbs/internal/adminaccess"
	"strings"
)

// Choice は送信用の値と画面に表示する意味を分離した選択肢。
type Choice struct{ Value, Label string }

var choices = map[string][]Choice{
	"report_state":    {{"open", "未対応"}, {"in_progress", "対応中"}, {"resolved", "対応済み"}, {"rejected", "却下"}, {"duplicate", "重複"}},
	"report_category": {{"normal", "通常削除"}, {"important", "重要削除"}, {"inquiry", "問い合わせ"}},
	"dns_status":      {{"unchecked", "未確認・取得待ち・一時エラー"}, {"confirmed", "逆引きと正引きが一致"}, {"absent", "PTRなし（逆引き不能）"}, {"mismatch", "PTR名が不正・正引き不一致"}},
	"slip": {
		{"none", "回線表示なし（ID末尾も非表示）"},
		{"checked", "ID末尾で従来の端末区分を表示（回線名なし）"},
		{"feature", "ID末尾で回線を区別（スマホ回線はSにまとめる）"},
		{"verbose", "ID末尾で回線を詳しく区別（回線名なし）"},
		{"vvv", "回線名を表示（識別子・IPなし）"},
		{"vvvv", "回線名とIPアドレスを表示"},
		{"vvvvv", "回線名と週ごとの識別子を表示（ワッチョイ）"},
		{"vvvvvv", "回線名・週ごとの識別子・IPアドレスを表示"},
	},
	"id":               {{"required", "常にIDを表示"}, {"optional", "メール欄が空の投稿でIDを表示"}, {"hidden", "IDを表示しない"}},
	"role":             administratorRoleChoices(),
	"admin_permission": administratorPermissionChoices(),
	"cap_permission":   {{"post", "返信する"}, {"create", "スレッドを作成する"}},
	"network":          {{"unknown", "不明・分類しない"}, {"fixed", "固定回線"}, {"mixed", "固定・携帯混在"}, {"mobile", "携帯回線"}, {"mvno", "MVNO（格安SIMなど）"}, {"wifi", "公衆Wi-Fi"}, {"academic", "大学・学術網"}, {"school", "学校"}, {"government", "官公庁"}, {"business", "企業内回線"}, {"hosting", "クラウド・VPS"}, {"satellite", "衛星回線"}, {"proxy", "プロキシ"}, {"vpn", "既知VPN"}, {"foreign", "国外IP"}},
	"rule_network":     {{"mobile", "携帯回線とMVNO"}, {"mvno", "MVNO（格安SIMなど）"}, {"fixed", "固定回線"}, {"mixed", "固定・携帯混在"}, {"wifi", "公衆Wi-Fi"}, {"academic", "大学・学術網"}, {"school", "学校"}, {"government", "官公庁"}, {"business", "企業内回線"}, {"hosting", "クラウド・VPS"}, {"satellite", "衛星回線"}, {"proxy", "プロキシ"}, {"vpn", "既知VPN"}, {"foreign", "国外IP"}, {"unknown", "回線種別が不明"}},
	"country":          {{"jp", "日本"}, {"foreign", "国外"}, {"unknown", "未確認"}, {"auto", "自動判定"}},
	"vpn":              {{"vpn", "既知VPN"}, {"direct", "既知VPNに該当しない"}, {"unknown", "未確認"}, {"auto", "自動判定"}},
	"cookie":           {{"off", "使用しない"}, {"optional", "任意"}, {"required", "必須"}},
	"boolean":          {{"true", "はい"}, {"false", "いいえ"}},
	"thread":           {{"active", "投稿受付中"}, {"stopped", "投稿停止"}, {"archived", "過去ログ"}, {"hidden", "公開停止"}, {"expired", "保持期限終了"}},
	"rule_field":       {{"ip", "IPアドレス"}, {"network", "IPの範囲"}, {"host", "投稿元ホスト名"}, {"line", "回線種別"}, {"name", "名前"}, {"mail", "メール"}, {"title", "タイトル"}, {"body", "本文"}, {"ua", "User-Agent"}, {"domain", "リンクのドメイン"}, {"token", "匿名利用者の識別情報"}},
	"rule_operator":    {{"exact", "完全一致"}, {"contains", "部分一致"}, {"regexp", "正規表現"}, {"cidr", "ネットワーク範囲"}, {"suffix", "ドメインとそのサブドメイン"}},
	"reason":           {{"manual", "運営判断"}, {"spam", "スパム"}, {"abuse", "荒らし"}},
	"deletion_phase":   {{"intent", "変更の準備中"}, {"public_stopped", "配信を停止して変更中"}, {"applied", "公開へ反映済み"}, {"cleaning", "公開へ反映済み・保存データを掃除中"}},
	"deletion":         {{"redact", "レス・タイトル削除"}, {"hide", "スレッド全体の公開停止"}, {"expire", "保持期限による終了"}},
}

// choiceLabel は内部値を説明へ変換する。未知の値は文字列のまま返し、テンプレート側でエスケープする。
func choiceLabel(group, value string) string {
	for _, option := range choices[group] {
		if option.Value == value {
			return option.Label
		}
	}
	return value
}

// displayMode は旧追加フラグを含む実際の公開内容を、一つの選択値へまとめる。
func displayMode(mode string, extraHash, extraIP bool) string {
	hash := extraHash || mode == "vvvvv" || mode == "vvvvvv"
	ip := extraIP || mode == "vvvv" || mode == "vvvvvv"
	switch {
	case hash && ip:
		return "vvvvvv"
	case hash:
		return "vvvvv"
	case ip:
		return "vvvv"
	case strings.HasPrefix(mode, "vvv"):
		return "vvv"
	default:
		return mode
	}
}

// idMode は旧必須bitを含む実効ID設定を管理画面に反映する。
func idMode(mode string, required bool) string {
	if required {
		return "required"
	}
	return mode
}

var templateFunctions = template.FuncMap{
	"dateNow":            dateNow,
	"dateRFC":            dateRFC,
	"formatBytes":        formatBytes,
	"formatMbps":         formatMbps,
	"roleIncludesExtras": adminaccess.IncludesExtras,
	"adminRoles":         adminaccess.Roles,
	"adminPermissions":   adminaccess.Permissions,
	"choiceLabel":        choiceLabel,
	"displayMode":        displayMode,
	"idMode":             idMode,
	"choices":            func(group string) []Choice { return choices[group] },
}

// administratorRoleChoices は認可側と同じロール定義を画面の選択肢へ渡す。
func administratorRoleChoices() []Choice {
	choices := []Choice{}
	for _, role := range adminaccess.Roles() {
		choices = append(choices, Choice{role.Value, role.Label})
	}
	return choices
}

// administratorPermissionChoices は実際に使える追加権限だけを表示する。
func administratorPermissionChoices() []Choice {
	choices := []Choice{}
	for _, permission := range adminaccess.Permissions() {
		choices = append(choices, Choice{permission.Value, permission.Label})
	}
	return choices
}

// ChoiceLabel は管理一覧のサーバー側検索・比較にもテンプレートと同じ表示名を返す。
func ChoiceLabel(group, value string) string { return choiceLabel(group, value) }
