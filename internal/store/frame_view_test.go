// 完成frameの参照検査とストリーム検査が、破損・切断・元入力の所有権を保つことを確認する。
package store

import (
	"bytes"
	"oimobbs/internal/domain"
	"reflect"
	"testing"
)

func TestFrameViewMatchesStream(t *testing.T) {
	raw, err := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte(`{"a":1}`), []byte("DAT\n")}, {domain.NewID(), []byte(`{"b":"値"}`), nil}}})
	if err != nil {
		t.Fatal(err)
	}
	check := func(raw []byte) {
		t.Helper()
		want, n, err := ReadFrame(bytes.NewReader(raw))
		got, actual := decodeFrameView(raw)
		valid := err == nil && n == int64(len(raw))
		if (actual == nil) != valid || valid && !reflect.DeepEqual(got, want) {
			t.Fatalf("検査不一致: stream=%v view=%v", err, actual)
		}
	}
	check(raw)
	for i := 0; i < len(raw); i++ {
		check(raw[:i])
		bad := bytes.Clone(raw)
		bad[i] ^= 1
		check(bad)
	}
	check(append(bytes.Clone(raw), 0))
	// ストリーム結果は入力と独立し、appendが別フィールドへ上書きしない。
	owned, _, err := ReadFrame(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(owned.Records[0].DAT)
	owned.Records[0].JSON = append(owned.Records[0].JSON, 'x')
	if !bytes.Equal(owned.Records[0].DAT, want) {
		t.Fatal("JSON追記がDATを変更した")
	}
	for i := range raw {
		raw[i] = 0
	}
	if !bytes.Equal(owned.Records[0].DAT, want) {
		t.Fatal("入力変更がstream結果へ波及した")
	}
}

func FuzzFrameViewMatchesStream(f *testing.F) {
	raw, _ := EncodeFrame(Frame{1, []Record{{domain.NewID(), []byte(`{"a":1}`), nil}}})
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		want, n, err := ReadFrame(bytes.NewReader(raw))
		got, actual := decodeFrameView(raw)
		valid := err == nil && n == int64(len(raw))
		if (actual == nil) != valid || valid && !reflect.DeepEqual(got, want) {
			t.Fatal("frame検査不一致", err, actual)
		}
	})
}
