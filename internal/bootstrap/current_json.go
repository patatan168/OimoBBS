// 現行保存JSONの全項目を出力し、選択なしの配列も明示する。
package bootstrap

import (
	"encoding/json"
	"oimobbs/internal/strictjson"
)

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v boardIdentity) MarshalJSON() ([]byte, error) {
	type plain boardIdentity
	out := plain(v)
	if out.Networks == nil {
		out.Networks = nilSliceElement(out.Networks)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *boardIdentity) UnmarshalJSON(raw []byte) error {
	type plain boardIdentity
	var next plain
	normalized, err := withLegacyDisplayCommands(raw)
	if err != nil {
		return err
	}
	if err := strictjson.Decode(normalized, &next); err != nil {
		return err
	}
	if len(next.Networks) == 0 {
		next.Networks = nil
	}
	*v = boardIdentity(next)
	return nil
}

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v NetworkConfig) MarshalJSON() ([]byte, error) {
	type plain NetworkConfig
	out := plain(v)
	if out.AccessOverrides == nil {
		out.AccessOverrides = nilSliceElement(out.AccessOverrides)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *NetworkConfig) UnmarshalJSON(raw []byte) error {
	type plain NetworkConfig
	var next plain
	if err := strictjson.Decode(raw, &next); err != nil {
		return err
	}
	if len(next.AccessOverrides) == 0 {
		next.AccessOverrides = nil
	}
	*v = NetworkConfig(next)
	return nil
}

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v NetworkAccessSettings) MarshalJSON() ([]byte, error) {
	type plain NetworkAccessSettings
	out := plain(v)
	if out.DeniedKinds == nil {
		out.DeniedKinds = nilSliceElement(out.DeniedKinds)
	}
	if out.DeniedCountries == nil {
		out.DeniedCountries = nilSliceElement(out.DeniedCountries)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *NetworkAccessSettings) UnmarshalJSON(raw []byte) error {
	type plain NetworkAccessSettings
	var next plain
	if err := strictjson.Decode(raw, &next); err != nil {
		return err
	}
	if len(next.DeniedKinds) == 0 {
		next.DeniedKinds = nil
	}
	if len(next.DeniedCountries) == 0 {
		next.DeniedCountries = nil
	}
	*v = NetworkAccessSettings(next)
	return nil
}

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v denialEffect) MarshalJSON() ([]byte, error) {
	type plain denialEffect
	out := plain(v)
	if out.IDs == nil {
		out.IDs = nilSliceElement(out.IDs)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *denialEffect) UnmarshalJSON(raw []byte) error {
	type plain denialEffect
	var next plain
	if err := strictjson.Decode(raw, &next); err != nil {
		return err
	}
	if len(next.IDs) == 0 {
		next.IDs = nil
	}
	*v = denialEffect(next)
	return nil
}

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v denialRule) MarshalJSON() ([]byte, error) {
	type plain denialRule
	out := plain(v)
	if out.Reports == nil {
		out.Reports = nilSliceElement(out.Reports)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *denialRule) UnmarshalJSON(raw []byte) error {
	type plain denialRule
	var next plain
	if err := strictjson.Decode(raw, &next); err != nil {
		return err
	}
	if len(next.Reports) == 0 {
		next.Reports = nil
	}
	*v = denialRule(next)
	return nil
}

// MarshalJSON は空配列を明示し、旧形式の項目省略を生成しない。
func (v AdminRuleInput) MarshalJSON() ([]byte, error) {
	type plain AdminRuleInput
	out := plain(v)
	if out.Extra == nil {
		out.Extra = nilSliceElement(out.Extra)
	}
	if out.Allowed == nil {
		out.Allowed = nilSliceElement(out.Allowed)
	}
	return json.Marshal(out)
}

// UnmarshalJSON は完全型だけを読み、空の選択を内部表現へ戻す。
func (v *AdminRuleInput) UnmarshalJSON(raw []byte) error {
	type plain AdminRuleInput
	var next plain
	if err := strictjson.Decode(raw, &next); err != nil {
		return err
	}
	if len(next.Extra) == 0 {
		next.Extra = nil
	}
	if len(next.Allowed) == 0 {
		next.Allowed = nil
	}
	*v = AdminRuleInput(next)
	return nil
}

// nilSliceElement は型を維持した空スライスを返す。
func nilSliceElement[T any](_ []T) []T { return []T{} }

// withLegacyDisplayCommands は旧識別設定の省略を継承へ戻す。未知・重複キーは許可しない。
func withLegacyDisplayCommands(raw []byte) ([]byte, error) {
	return withLegacyOptionalField(raw, "display_commands")
}

// withLegacyOptionalField は旧JSONで未導入の項目だけをnullへ補完する。
func withLegacyOptionalField(raw []byte, field string) ([]byte, error) {
	if err := strictjson.Validate(raw); err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if _, exists := obj[field]; exists {
		return raw, nil
	}
	obj[field] = json.RawMessage("null")
	return json.Marshal(obj)
}

// UnmarshalJSON は転載・隠し板設定導入前の保存形式をOFFとして読み込む。
func (v *boardPresentation) UnmarshalJSON(raw []byte) error {
	type plain boardPresentation
	normalized, err := withLegacyOptionalField(raw, "no_reprint")
	if err != nil {
		return err
	}
	normalized, err = withLegacyOptionalField(normalized, "hidden")
	if err != nil {
		return err
	}
	var next plain
	if err := strictjson.Decode(normalized, &next); err != nil {
		return err
	}
	*v = boardPresentation(next)
	return nil
}

// UnmarshalJSON は旧管理APIの転載・隠し板・通報設定省略を既存値の維持として扱う。
func (v *AdminBoardEdit) UnmarshalJSON(raw []byte) error {
	type plain AdminBoardEdit
	normalized, err := withLegacyOptionalField(raw, "auto_reports_enabled")
	if err != nil {
		return err
	}
	normalized, err = withLegacyOptionalField(normalized, "no_reprint")
	if err != nil {
		return err
	}
	normalized, err = withLegacyOptionalField(normalized, "hidden")
	if err != nil {
		return err
	}
	var next plain
	if err := strictjson.Decode(normalized, &next); err != nil {
		return err
	}
	*v = AdminBoardEdit(next)
	return nil
}

// UnmarshalJSON は旧板の通報設定省略を有効として読み、未知キー・重複・型不正を拒否する。
func (v *boardPosting) UnmarshalJSON(raw []byte) error {
	type plain boardPosting
	normalized, err := withLegacyOptionalField(raw, "auto_reports")
	if err != nil {
		return err
	}
	var next plain
	if err := strictjson.Decode(normalized, &next); err != nil {
		return err
	}
	*v = boardPosting(next)
	return nil
}
