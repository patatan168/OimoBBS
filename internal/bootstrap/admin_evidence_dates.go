// 証拠管理APIの日時入力を保存形式へ変換し、旧ns入力との固定再送を維持する。
package bootstrap

import (
	"encoding/json"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

// evidenceRequestDates は重複キー検査後の要求だけを変換する。保存・署名型を変更しない。
func evidenceRequestDates(raw []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	if err := evidenceDateField(fields, "hold_until", "hold_until_ns"); err != nil {
		return nil, err
	}
	for object, dates := range map[string][]string{"scope": {"from", "to"}, "transfer": {"transferred_at"}} {
		value, ok := fields[object]
		if !ok || string(value) == "null" {
			continue
		}
		converted, err := evidenceObjectDates(value, dates)
		if err != nil {
			return nil, err
		}
		fields[object] = converted
	}
	return json.Marshal(fields)
}

// evidenceObjectDates は指定された日時だけを変換し、未知キーを後続の厳密decodeへ残す。
func evidenceObjectDates(raw []byte, dates []string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, name := range dates {
		if err := evidenceDateField(fields, name, name+"_ns"); err != nil {
			return nil, err
		}
	}
	return json.Marshal(fields)
}

// evidenceDateField はRFC3339Nanoをnsへ正確に変換し、二重指定・null・範囲外を拒否する。
func evidenceDateField(fields map[string]json.RawMessage, name, legacy string) error {
	value, present := fields[name]
	if !present {
		return nil
	}
	if _, duplicate := fields[legacy]; duplicate {
		return disclosure.ErrInvalid
	}
	var text string
	if json.Unmarshal(value, &text) != nil || text == "" {
		return disclosure.ErrInvalid
	}
	at, err := time.Parse(time.RFC3339Nano, text)
	if err != nil || at.UnixNano() < 0 || !time.Unix(0, at.UnixNano()).Equal(at) {
		return disclosure.ErrInvalid
	}
	encoded, err := json.Marshal(domain.Time(at.UnixNano()))
	if err != nil {
		return err
	}
	delete(fields, name)
	fields[legacy] = encoded
	return nil
}
