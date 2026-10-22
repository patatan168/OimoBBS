// 説明付きの選択欄を既存の管理API入力へ正規化し、旧フォームも受け付ける。
package bootstrap

import (
	"encoding/json"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postinput"
	"slices"
	"sort"
	"strings"
)

// normalizePermissionSelection は空のチェック集合も明示保存し、未知値・重複を拒否する。
func normalizePermissionSelection(v url.Values, name string) error {
	if !v.Has("permission_selection") {
		return nil
	}
	if len(v["permission_selection"]) != 1 || v.Get("permission_selection") != "1" {
		return ErrPostingRequest
	}
	allowed := adminExtraPermissions
	if name == "permissions" {
		allowed = map[string]bool{"post": true, "create": true}
	}
	if len(v[name]) == 1 && v.Get(name) == "" {
		v.Del(name)
	}
	seen := map[string]bool{}
	for _, value := range v[name] {
		if !allowed[value] || seen[value] {
			return ErrPostingRequest
		}
		seen[value] = true
	}
	values := append([]string{}, v[name]...)
	sort.Strings(values)
	v.Set(name, strings.Join(values, " "))
	v.Del("permission_selection")
	return nil
}

// normalizeBoardNetworkRows は編集欄から最大512行の板上書きを作り、JSON入力を不要にする。
func normalizeBoardNetworkRows(v url.Values) error {
	if !v.Has("network_rows") {
		return nil
	}
	if len(v["network_rows"]) != 1 || v.Get("network_rows") != "1" || v.Has("network_classes") {
		return ErrPostingRequest
	}
	names := []string{"network_cidr", "network_kind", "network_label", "network_suffix"}
	if v.Has("network_provider") {
		names = append(names, "network_provider")
	}
	count := len(v["network_cidr"])
	if count == 0 || count > 513 {
		return ErrPostingRequest
	}
	for _, name := range names {
		if len(v[name]) != count {
			return ErrPostingRequest
		}
	}
	rows := []identity.NetworkClass{}
	for i, cidr := range v["network_cidr"] {
		label, suffix := strings.TrimSpace(v["network_label"][i]), strings.TrimSpace(v["network_suffix"][i])
		provider := ""
		if v.Has("network_provider") {
			provider = strings.TrimSpace(v["network_provider"][i])
		}
		if strings.TrimSpace(cidr) == "" && label == "" && suffix == "" && provider == "" {
			continue
		}
		prefix, err := canonicalNetworkCIDR(cidr)
		if err != nil {
			prefix = strings.TrimSpace(cidr)
		}
		kind := v["network_kind"][i]
		fallbackLabel, fallbackSuffix := identity.DefaultNetworkDisplay(kind)
		if label == "" {
			label = fallbackLabel
		}
		if suffix == "" {
			suffix = fallbackSuffix
		}
		rows = append(rows, identity.NetworkClass{CIDR: prefix, Kind: kind, Label: label, Suffix: suffix, Provider: provider})
	}
	// 値の業務検査は既存の設定保存処理へ渡す。エラー時にも行の入力を再表示する。
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	v.Set("network_classes", string(raw))
	for _, name := range names {
		v.Del(name)
	}
	v.Del("network_rows")
	return nil
}

// NetworkRows は保存値/エラー時の入力を行編集へ戻し、JSなしでも追加できる空行を付ける。
func (p adminBoardsPage) NetworkRows() []identity.NetworkClass {
	rows := []identity.NetworkClass{}
	_ = json.Unmarshal([]byte(p.Values.Get("network_classes")), &rows)
	if len(rows) < 512 {
		rows = append(rows, identity.NetworkClass{Kind: "unknown"})
	}
	return rows
}

// PermissionChecked は追加権限の保存値をチェック状態へ戻す。
func (a AdminAccount) PermissionChecked(value string) bool {
	return slices.Contains(a.Access.Permissions, value)
}

// normalizeRuleNetworkChoices は回線種別の説明付き選択欄を既存の条件値へ変換する。
func normalizeRuleNetworkChoices(v url.Values) error {
	for _, row := range []struct{ choice, field, target string }{{"line_target", "field", "target"}, {"line_extra", "extra_field", "extra_value"}} {
		if !v.Has(row.choice) {
			continue
		}
		value := v.Get(row.choice)
		if len(v[row.field]) != 1 || len(v[row.target]) != 1 {
			return ErrPostingRequest
		}
		if len(v[row.choice]) != 1 || !identity.ValidNetworkKind(value) {
			return ErrPostingRequest
		}
		if v.Get(row.field) == "line" {
			v.Set(row.target, value)
		}
		v.Del(row.choice)
	}
	return nil
}

// normalizeDisplaySelection は新しい単一選択を優先し、旧追加フラグの持ち越しを防ぐ。
// マーカーのない旧フォーム/APIでは独立フラグの意味を維持する。
func normalizeDisplaySelection(v url.Values, thread bool) error {
	if !v.Has("display_selection") {
		return nil
	}
	if len(v["display_selection"]) != 1 || v.Get("display_selection") != "1" || len(v["slip_mode"]) != 1 || v.Has("require_public_ip") || v.Has("require_slip_hash") {
		return ErrPostingRequest
	}
	if !slices.Contains([]string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}, v.Get("slip_mode")) {
		return ErrPostingRequest
	}
	v.Set("require_public_ip", "false")
	if thread {
		v.Set("require_slip_hash", "false")
	}
	v.Del("display_selection")
	return nil
}

// normalizeIDSelection は単一のID選択を既存ポリシーへ変換し、二重指定を拒否する。
func normalizeIDSelection(v url.Values) error {
	if !v.Has("id_selection") {
		return nil
	}
	if len(v["id_selection"]) != 1 || v.Get("id_selection") != "1" || len(v["id_mode"]) != 1 || v.Has("require_id") {
		return ErrPostingRequest
	}
	if !slices.Contains([]string{"required", "optional", "hidden"}, v.Get("id_mode")) {
		return ErrPostingRequest
	}
	v.Set("require_id", "false")
	v.Del("id_selection")
	return nil
}

// normalizeDisplayCommands は個別チェックを保存用JSONへ変換し、全OFFも保持する。
func normalizeDisplayCommands(v url.Values) error {
	if !v.Has("display_command_selection") {
		if !v.Has("display_commands") {
			v.Set("display_commands", "null")
		}
		return nil
	}
	if len(v["display_command_selection"]) != 1 || v.Get("display_command_selection") != "1" {
		return ErrPostingRequest
	}
	names := append([]string{}, v["display_commands"]...)
	if postinput.ValidateDisplayCommands(names) != nil {
		return ErrPostingRequest
	}
	sort.Strings(names)
	raw, _ := json.Marshal(names)
	v.Set("display_commands", string(raw))
	v.Del("display_command_selection")
	return nil
}
