// 条件付き追加枠を受理記録へ固定し、復旧時に入力から再評価できるようにする。
package postcapture

import (
	"encoding/json"
	"oimobbs/internal/domain"
)

func validOverrides(ids []domain.ID) bool {
	if len(ids) < 1 || len(ids) > 12 {
		return false
	}
	prior := ""
	for _, id := range ids {
		if id == (domain.ID{}) || id.String() <= prior {
			return false
		}
		prior = id.String()
	}
	return true
}

// WithOverrides は秘密を持たない追加規制IDを結合する。Cookie成分の結合後にframeを検証する。
func WithOverrides(raw []byte, ids []domain.ID) ([]byte, error) {
	if !validOverrides(ids) {
		return nil, ErrCapture
	}
	c, err := decode(raw)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields["schema"], _ = json.Marshal(Schema)
	fields["token"], _ = json.Marshal(c.Token)
	fields["cap"], _ = json.Marshal(c.Cap)
	fields["overrides"], _ = json.Marshal(ids)
	return json.Marshal(fields)
}

// OverrideMetadata は検証済み成分から受理時の規制条件と追加IDを複製する。
// 従来のHTTP観測・管理操作captureは対象外として返す。
func OverrideMetadata(raw []byte) (*Capture, *TokenEvidence, []domain.ID, error) {
	schema, err := schemaOf(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	if schema != Schema {
		return nil, nil, nil, nil
	}
	c, err := decode(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	return &c.Capture, c.Token, append([]domain.ID{}, c.Overrides...), nil
}
