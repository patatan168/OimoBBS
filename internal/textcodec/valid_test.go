// Shift_JISの検証専用経路を既存の復号と全1・2byte値および長い入力で照合する。
package textcodec

import (
	"bytes"
	"testing"
)

func TestValidMatchesDecode(t *testing.T) {
	check := func(b []byte) {
		t.Helper()
		_, err := Decode(b)
		if got := Valid(b); got != (err == nil) {
			t.Fatalf("%x: Valid=%v Decode=%v", b, got, err)
		}
	}
	check(nil)
	for first := range 256 {
		check([]byte{byte(first)})
		for second := range 256 {
			check([]byte{byte(first), byte(second)})
		}
	}
	for _, n := range []int{7, 8, 9, 15, 16, 17, 63, 64, 65} {
		for pos := 0; pos < n; pos++ {
			for _, inserted := range [][]byte{{0x80}, {0xff}, {0x81}, {0x81, 0x7f}, {0x82, 0xa0}, {0xf0, 0x40}, {0xfc, 0xfc}} {
				body := bytes.Repeat([]byte{'a'}, n)
				copy(body[pos:], inserted)
				check(body)
			}
		}
	}
}

func FuzzValidMatchesDecode(f *testing.F) {
	for _, b := range [][]byte{nil, []byte("name<><>date<>body<>title\n"), {0x80, 0xa1, 0xdf}, {0x82, 0xa0}, {0xf0, 0x40}, {0x81, 0x7f}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, err := Decode(b)
		if Valid(b) != (err == nil) {
			t.Fatalf("validation differs for %x: %v", b, err)
		}
	})
}
