// 文字変換の独立既知値と不正バイトを検査する。
package textcodec

import (
	"encoding/hex"
	"testing"
)

func TestKnown(t *testing.T) {
	for _, v := range [][2]string{{"日本語", "93fa967b8cea"}, {"あいう", "82a082a282a4"}, {"ｱｲｳ", "b1b2b3"}, {"水", "9085"}, {"～", "8160"}, {"髙", "fbfc"}} {
		b, err := Encode(v[0], false)
		if err != nil || hex.EncodeToString(b) != v[1] {
			t.Errorf("%s: %x %v", v[0], b, err)
		}
		s, err := Decode(b)
		if err != nil || s != v[0] {
			t.Fatal(s, err)
		}
	}
}
func TestInvalidAndFallback(t *testing.T) {
	for _, b := range [][]byte{{0x81}, {0x81, 0x7f}, {0xff}, {0x80, 0x81, 0x20}} {
		if _, e := Decode(b); e == nil {
			t.Errorf("accepted %x", b)
		}
	}
	if b, e := Encode("😀", true); e != nil || string(b) != "&#128512;" {
		t.Fatal(string(b), e)
	}
	if _, e := Encode("😀", false); e == nil {
		t.Fatal("secret substituted")
	}
	b, _ := Encode("¥‾−", false)
	if hex.EncodeToString(b) != "5c7e817c" {
		t.Fatalf("%x", b)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0x82, 0xa0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b) })
}
