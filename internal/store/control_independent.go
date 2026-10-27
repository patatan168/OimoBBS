// journal新規行の独立検証をCPUへ分担し、書込み前に全結果を入力順へ照合する。
package store

import (
	"bytes"
	"oimobbs/internal/parallel"
	"slices"
)

// validateIndependentValues は現在行も先行候補も参照しない新規行だけを許可する。
// 全worker終了まで状態・fileを変更せず、同じprivateな復号結果だけを後続の順序適用へ渡す。
func (c *ControlLog) validateIndependentValues(decoded []preparedControlOperation) error {
	if c.validator == nil {
		return ErrCorrupt
	}
	if err := c.checkIndependentValues(decoded); err != nil {
		return err
	}
	errs := make([]error, len(decoded))
	parallel.CPU(len(decoded), func(i int) {
		m := decoded[i].op.Mutations[0]
		value := bytes.TrimSpace(m.Value)
		if err := c.validator(m.Collection, m.Key, nil, value); err != nil {
			errs[i] = err
			return
		}
		errs[i] = validateStoredControlValue(m.Collection, m.Key, value)
	})
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// checkIndependentValues は値検証を呼ぶ前に、新規行だけで構成されるか確認する。
func (c *ControlLog) checkIndependentValues(decoded []preparedControlOperation) error {
	seen := make(map[string]bool, len(decoded))
	for _, entry := range decoded {
		if len(entry.op.Mutations) != 1 {
			return ErrCorrupt
		}
		m := entry.op.Mutations[0]
		key := m.Collection + ":" + m.Key
		value := bytes.TrimSpace(m.Value)
		if !slices.Contains(controlCollections[c.header.Kind], m.Collection) || len(m.Key) > 160 || !controlKey.MatchString(m.Key) || m.ExpectedRevision != 0 || m.Expires != nil || len(value) == 0 || bytes.Equal(value, []byte("null")) || seen[key] {
			return ErrCorrupt
		}
		if _, exists := c.state.Rows[key]; exists {
			return ErrCorrupt
		}
		seen[key] = true
	}
	return nil
}
