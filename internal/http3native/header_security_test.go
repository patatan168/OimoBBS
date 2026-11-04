// 不正なfieldと設定の解釈差を防ぎ、HTTP/3の入力境界を検査する。
package http3native

import (
	"bytes"
	"testing"
)

func TestHTTP3AmbiguousFieldsAreRejected(t *testing.T) {
	base := []Field{{":method", "GET"}, {":scheme", "https"}, {":authority", "localhost"}, {":path", "/"}}
	for _, fields := range [][]Field{
		{{"host", ""}},
		{{"host", ""}, {"host", "localhost"}},
		{{"x-test", " leading"}},
		{{"x-test", "trailing\t"}},
	} {
		t.Run(fields[0].Name+fields[0].Value, func(t *testing.T) {
			input := append(append([]Field(nil), base...), fields...)
			if _, err := requestFields(input, t.Context()); err == nil {
				t.Fatalf("ambiguous fields accepted: %+v", fields)
			}
		})
	}
	for _, field := range []Field{{"host", "localhost"}, {"x-test", ""}, {"x-test", "inside\ttab"}} {
		if _, err := requestFields(append(append([]Field(nil), base...), field), t.Context()); err != nil {
			t.Errorf("valid field rejected: %+v: %v", field, err)
		}
	}
}

// FuzzQPACKInstructions は両方向の制御命令と動的tableの上限を検査する。
func FuzzQPACKInstructions(f *testing.F) {
	f.Add(false, []byte{0x20})
	f.Add(false, append(appendPrefix(nil, 0x20, 5, 4096), []byte{0x41, 'x', 1, 'y'}...))
	f.Add(true, []byte{0x40})
	f.Add(true, []byte{0x80})
	f.Fuzz(func(t *testing.T, decoder bool, data []byte) {
		if len(data) > 64<<10 {
			return
		}
		q := newQPACK(nil, nil)
		if decoder {
			_ = q.readDecoder(bytes.NewReader(data))
		} else {
			_ = q.readEncoder(bytes.NewReader(data))
		}
		if q.rx.size > 4096 || len(q.rx.entries) > 128 || len(q.sections) > 128 {
			t.Fatal("QPACK resource budget exceeded")
		}
	})
}

func TestHTTP3ReservedSettingsAreRejected(t *testing.T) {
	for _, id := range []uint64{0, 2, 3, 4, 5} {
		c := &connection{qpack: newQPACK(nil, nil)}
		if err := c.settingsFrame(append(integer(id), integer(0)...)); err == nil {
			t.Errorf("reserved setting %d accepted", id)
		}
	}
}
