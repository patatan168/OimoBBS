// 板別のコマンド許可一覧を検査する。省略時だけ従来の一括許可を引き継ぐ。
package postinput

import (
	"oimobbs/internal/domain"
	"slices"
	"strings"
)

// DisplayCommandNames は個別に許可できる正規形のコマンド36種類を返す。
func DisplayCommandNames() []string {
	modes := []string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}
	names := []string{"!id:on"}
	for _, mode := range modes {
		names = append(names, "!slip:"+mode)
	}
	for _, mode := range append([]string{"default"}, modes...) {
		for _, id := range []string{"default", "checked", "none"} {
			names = append(names, "!extend:"+id+":"+mode+"::")
		}
	}
	return names
}

// ValidateDisplayCommands は未知・別名・重複を拒否する。空一覧は全コマンドOFF。
func ValidateDisplayCommands(names []string) error {
	supported := DisplayCommandNames()
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] || !slices.Contains(supported, name) {
			return ErrInput
		}
		seen[name] = true
	}
	return nil
}

// CheckDisplayCommands は実際に適用する命令すべての許可を検査する。
// allowed=nilは旧設定を継承する。空の一覧は通常投稿だけを許可する。
// !extendの空指定はdefaultへ正規化し、別名によるOFFの迂回を防ぐ。
func CheckDisplayCommands(c *Controls, allowed *[]string) error {
	if c == nil || allowed == nil {
		return nil
	}
	if c.Thread {
		id, slip := "default", c.Slip
		if c.ID == "on" {
			id = "checked"
		}
		if c.ID == "off" {
			id = "none"
		}
		if slip == "" {
			slip = "default"
		}
		if !slices.Contains(*allowed, "!extend:"+id+":"+slip+"::") {
			return ErrInput
		}
		return nil
	}
	if c.ID != "" && !slices.Contains(*allowed, "!id:"+c.ID) {
		return ErrInput
	}
	if c.Slip != "" && !slices.Contains(*allowed, "!slip:"+c.Slip) {
		return ErrInput
	}
	return nil
}

// DisplayCommandCompatible は板の表示条件で受理できる正規形の命令かを返す。
// 個別ON/OFFとは別に、投稿処理と同じ弱化・必須IDの検査を使う。
func DisplayCommandCompatible(p domain.Policy, command string) bool {
	if ValidateDisplayCommands([]string{command}) != nil {
		return false
	}
	name, body := command, ""
	if strings.HasPrefix(command, "!extend:") {
		name, body = "", command+"\n本文"
	}
	_, _, controls, err := parseControls(name, body, true)
	if err != nil {
		return false
	}
	_, err = DisplayPolicy(p, controls, true)
	return err == nil
}
