// 板全体の回線・登録国の許可を、個別の期限付き規制から分離する。
package bootstrap

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"slices"
	"strings"
)

var permissionKinds = []ruleFieldOption{{"fixed", "固定回線"}, {"mixed", "固定・携帯混在"}, {"mobile", "携帯回線"}, {"mvno", "MVNO"}, {"wifi", "公衆Wi-Fi"}, {"academic", "大学・学術網"}, {"school", "学校"}, {"government", "官公庁"}, {"business", "企業内回線"}, {"hosting", "クラウド・VPS"}, {"satellite", "衛星回線"}, {"proxy", "プロキシ"}, {"unknown", "回線種別が不明"}}

// validate は現行保存形式の許可設定を検査し、重複・未知種別・不正国コードを拒否する。
func (v *NetworkAccessSettings) validate() error {
	if v == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, kind := range v.DeniedKinds {
		valid := false
		for _, option := range permissionKinds {
			valid = valid || option.Value == kind
		}
		if !valid || seen[kind] {
			return store.ErrCorrupt
		}
		seen[kind] = true
	}
	if len(v.DeniedCountries) > 676 {
		return store.ErrCorrupt
	}
	seen = map[string]bool{}
	for _, code := range v.DeniedCountries {
		if !identity.ValidCountryCode(code) || seen[code] {
			return store.ErrCorrupt
		}
		seen[code] = true
	}
	return nil
}

func (v *NetworkAccessSettings) extended() bool {
	return v != nil && (v.DeniedKinds != nil || v.DeniedCountries != nil)
}

// PermissionKinds はチェックボックスに表示する回線種別を返す。
func (p adminBoardsPage) PermissionKinds() []ruleFieldOption { return permissionKinds }

// KindAllowed は未設定のとき許可を既定にする。
func (p adminBoardsPage) KindAllowed(kind string) bool {
	var denied []string
	_ = json.Unmarshal([]byte(p.Values.Get("denied_kinds")), &denied)
	return !slices.Contains(denied, kind)
}

// CountryAllowed は保存済みの国別拒否をチェック状態へ戻す。
func (p adminBoardsPage) CountryAllowed(code string) bool {
	var denied []string
	_ = json.Unmarshal([]byte(p.Values.Get("denied_countries")), &denied)
	return !slices.Contains(denied, code)
}

// permissionCountries は取得済み国と保存済みの拒否国を合成し、表更新後も選択を失わない。
func (h *adminHandler) permissionCountries(fields url.Values) []string {
	codes := []string{"JP", "US", "CN", "KR", "TW", "GB", "DE", "FR", "RU"}
	if t := h.repo.liveNetworks.Load(); t != nil && t.Access != nil {
		codes = append(codes, t.Access.Countries.Codes()...)
	}
	var denied []string
	_ = json.Unmarshal([]byte(fields.Get("denied_countries")), &denied)
	codes = append(codes, denied...)
	slices.Sort(codes)
	return slices.Compact(codes)
}

// readBoardPermissionForm はチェック省略を拒否へ正規化し、旧フォームの厳密検査を維持する。
func readBoardPermissionForm(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	if e := r.ParseForm(); e != nil {
		return nil, e
	}
	// 本文だけを扱い、URLクエリを設定値として使わない。
	v := r.PostForm
	if !v.Has("auto_reports_enabled") {
		v.Set("auto_reports_enabled", "null")
	}
	if !v.Has("hidden") {
		v.Set("hidden", "null")
	}
	if !v.Has("no_reprint") {
		v.Set("no_reprint", "null")
	}
	if err := normalizeDisplayCommands(v); err != nil {
		return nil, err
	}
	if err := normalizeDisplaySelection(v, false); err != nil {
		return nil, err
	}
	if err := normalizeBoardNetworkRows(v); err != nil {
		return nil, err
	}
	if !v.Has("access_options") {
		r.Body = io.NopCloser(strings.NewReader(v.Encode()))
		names := adminBoardFormNames(v)
		if v.Has("deny_unresolved_host") {
			names = append(names, "deny_unresolved_host")
		}
		return adminForm(w, r, 256<<10, names...)
	}
	if len(v["access_options"]) != 1 || v.Get("access_options") != "1" {
		return nil, ErrPostingRequest
	}
	v.Del("access_options")
	allowed := func(name string) (bool, error) {
		values := v[name]
		v.Del(name)
		if len(values) == 0 {
			return false, nil
		}
		if len(values) != 1 || values[0] != "on" {
			return false, ErrPostingRequest
		}
		return true, nil
	}
	foreign, e := allowed("permit_foreign")
	if e != nil {
		return nil, e
	}
	vpn, e := allowed("permit_vpn")
	if e != nil {
		return nil, e
	}
	v.Set("japan_only", strconvBool(!foreign))
	v.Set("allow_vpn", strconvBool(vpn))
	if v.Has("reverse_options") {
		if len(v["reverse_options"]) != 1 || v.Get("reverse_options") != "1" {
			return nil, ErrPostingRequest
		}
		v.Del("reverse_options")
		permit, err := allowed("permit_unresolved_host")
		if err != nil {
			return nil, err
		}
		v.Set("deny_unresolved_host", strconvBool(!permit))
	}
	denied := []string{}
	for _, option := range permissionKinds {
		permit, e := allowed("permit_kind_" + option.Value)
		if e != nil {
			return nil, e
		}
		if !permit {
			denied = append(denied, option.Value)
		}
	}
	if len(v["country_scope"]) != 1 {
		return nil, ErrPostingRequest
	}
	scope := strings.Fields(v.Get("country_scope"))
	v.Del("country_scope")
	if len(scope) == 0 || len(scope) > 676 {
		return nil, ErrPostingRequest
	}
	seen := map[string]bool{}
	for _, code := range scope {
		if !identity.ValidCountryCode(code) || seen[code] {
			return nil, ErrPostingRequest
		}
		seen[code] = true
	}
	permitted := map[string]bool{}
	for _, code := range v["allow_country"] {
		if !seen[code] || permitted[code] {
			return nil, ErrPostingRequest
		}
		permitted[code] = true
	}
	v.Del("allow_country")
	countries := []string{}
	for _, code := range scope {
		if !permitted[code] {
			countries = append(countries, code)
		}
	}
	slices.Sort(countries)
	raw, _ := json.Marshal(denied)
	v.Set("denied_kinds", string(raw))
	raw, _ = json.Marshal(countries)
	v.Set("denied_countries", string(raw))
	r.Body = io.NopCloser(strings.NewReader(v.Encode()))
	names := append(adminBoardFormNames(v), "denied_kinds", "denied_countries")
	if v.Has("deny_unresolved_host") {
		names = append(names, "deny_unresolved_host")
	}
	return adminForm(w, r, 256<<10, names...)
}
func strconvBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// adminBoardFormNames は画面から外した旧設定を、全項目省略時だけ既存値の維持として受け付ける。
// 一部だけ送った旧設定、未知項目、重複項目はadminFormの厳格検査で拒否する。
func adminBoardFormNames(v url.Values) []string {
	omitted := map[string]bool{}
	for _, group := range [][]string{
		{"cookie_mode", "token_wait_seconds"},
		{"rate_enabled", "reply_seconds", "reply_burst", "create_seconds", "create_burst", "create_window_limit"},
	} {
		present := false
		for _, name := range group {
			present = present || v.Has(name)
		}
		if !present {
			for _, name := range group {
				omitted[name] = true
			}
		}
	}
	names := make([]string, 0, len(adminBoardFieldNames))
	for _, name := range adminBoardFieldNames {
		if !omitted[name] {
			names = append(names, name)
		}
	}
	return names
}
