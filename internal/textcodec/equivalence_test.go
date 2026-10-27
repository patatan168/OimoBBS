// 変換結果・拒否条件・エラー位置を変更前の実装と照合する。
package textcodec

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

func sameError(a, b error) bool {
	return a == nil && b == nil || a != nil && b != nil && a.Error() == b.Error()
}

func TestDecodeMatchesPrevious(t *testing.T) {
	check := func(b []byte) {
		t.Helper()
		want, wantErr := referenceDecode(b)
		got, err := Decode(b)
		if got != want || !sameError(err, wantErr) {
			t.Fatalf("%x: got %q/%v want %q/%v", b, got, err, want, wantErr)
		}
	}
	check(nil)
	for first := range 256 {
		check([]byte{byte(first)})
		for second := range 256 {
			check([]byte{byte(first), byte(second)})
		}
	}
}

func TestEncodeMatchesPrevious(t *testing.T) {
	for r := rune(0); r <= 0xffff; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		for _, allow := range []bool{false, true} {
			s := "prefix" + string(r) + "suffix"
			want, wantErr := referenceEncode(s, allow)
			got, err := Encode(s, allow)
			if !bytes.Equal(got, want) || !sameError(err, wantErr) {
				t.Fatalf("U+%04X allow=%v: got %x/%v want %x/%v", r, allow, got, err, want, wantErr)
			}
		}
	}
	for _, s := range []string{"😀", "𠮷", "\U0010ffff", "😀\xff", "abc\xc0\x80", "\xff😀"} {
		for _, allow := range []bool{false, true} {
			want, wantErr := referenceEncode(s, allow)
			got, err := Encode(s, allow)
			if !bytes.Equal(got, want) || !sameError(err, wantErr) {
				t.Fatalf("%q allow=%v differs", s, allow)
			}
		}
	}
}

func FuzzConversionMatchesPrevious(f *testing.F) {
	for _, b := range [][]byte{nil, []byte("ASCII\n"), []byte("日本語 ¥‾− 😀 𠮷"), {0x80, 0x82, 0xa0}, {0x81, 0x7f}} {
		f.Add(b)
	}
	f.Add([]byte(strings.Repeat("日本語😀ABC123\n", 8192)))
	f.Add(bytes.Repeat([]byte{0x82, 0xa0, 0x93, 0xfa, 'A', 0xa1}, 24000))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		want, wantErr := referenceDecode(b)
		got, err := Decode(b)
		if got != want || !sameError(err, wantErr) {
			t.Fatal("decode differs", err, wantErr)
		}
		for _, allow := range []bool{false, true} {
			want, wantErr := referenceEncode(string(b), allow)
			got, err := Encode(string(b), allow)
			if !bytes.Equal(got, want) || !sameError(err, wantErr) {
				t.Fatal("encode differs", allow, err, wantErr)
			}
		}
	})
}
