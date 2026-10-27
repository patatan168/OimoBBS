// 外形検査と完全型適用を分けても、不正JSONを従来の破損エラーとして返すことを確認する。
package store

import (
	"errors"
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func TestTypedFramePreservesJSONCorruptionClass(t *testing.T) {
	for _, body := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":"\u0000"}`, `{"a":1} x`} {
		t.Run(body, func(t *testing.T) {
			raw, err := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte("{}" + strings.Repeat(" ", len(body)-2)), nil}}})
			if err != nil {
				t.Fatal(err)
			}
			copy(raw[40:], body)
			n := int(le.Uint32(raw))
			le.PutUint32(raw[8+n:], checksum(raw[8:8+n]))
			_, validation := ValidateThreadFrame(nil, raw)
			_, group := prepareThreadGroup(ThreadAppend{Log: &ThreadLog{}, Frames: [][]byte{raw}})
			for name, err := range map[string]error{"candidate": validation, "group": group, "control": decodeControlCandidate(raw).err} {
				if !errors.Is(err, ErrCorrupt) {
					t.Errorf("%s: corrupt classification lost: %v", name, err)
				}
			}
		})
	}
}
