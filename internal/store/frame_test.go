// 設計fixtureと各byte切断位置からフレーム実装を検証する。
package store

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"os"
	"testing"
)

func TestFrameFixture(t *testing.T) {
	b, e := os.ReadFile("../../docs/design/fixtures/wal-v2-layout.json")
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Header struct {
			Hex string `json:"hex"`
		} `json:"wal_header"`
		Frame struct {
			Hex string `json:"hex"`
		} `json:"frame"`
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	hb, _ := hex.DecodeString(fixture.Header.Hex)
	h, e := DecodeHeader(hb)
	if e != nil {
		t.Fatal(e)
	}
	got, e := EncodeHeader(h)
	if e != nil || !bytes.Equal(got, hb) {
		t.Fatal("header mismatch", e)
	}
	fb, _ := hex.DecodeString(fixture.Frame.Hex)
	f, _, e := ReadFrame(bytes.NewReader(fb))
	if e != nil {
		t.Fatal(e)
	}
	got, e = EncodeFrame(f)
	if e != nil || !bytes.Equal(got, fb) {
		t.Fatal("frame mismatch", e)
	}
	for i := 0; i < len(fb); i++ {
		_, _, e = ReadFrame(bytes.NewReader(fb[:i]))
		want := ErrIncomplete
		if i == 0 {
			want = io.EOF
		}
		if !errors.Is(e, want) {
			t.Fatalf("cut %d: %v", i, e)
		}
	}
	for i := range fb {
		bad := bytes.Clone(fb)
		bad[i] ^= 1
		if _, _, e = ReadFrame(bytes.NewReader(bad)); e == nil || errors.Is(e, ErrIncomplete) {
			t.Fatalf("corruption %d: %v", i, e)
		}
	}
}
func FuzzFrame(f *testing.F) {
	b, _ := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte(`{"a":1}`), nil}}})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = ReadFrame(bytes.NewReader(b)) })
}
