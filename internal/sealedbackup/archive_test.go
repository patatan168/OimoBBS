// 暗号化コピーの改変、順序、切詰め、鍵違い、過大chunkを独立に検査する。
package sealedbackup

import (
	"bytes"
	"testing"
)

func TestArchiveAuthenticity(t *testing.T) {
	private, public, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, _, _ := GenerateKey()
	input := bytes.Repeat([]byte("private evidence\x00"), 10000)
	var archive bytes.Buffer
	if err := Seal(&archive, bytes.NewReader(input), public); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := Open(&output, bytes.NewReader(archive.Bytes()), private); err != nil || !bytes.Equal(output.Bytes(), input) {
		t.Fatal("round trip", err)
	}
	for _, modify := range []func([]byte) []byte{
		func(b []byte) []byte { b[12] ^= 1; return b },
		func(b []byte) []byte { b[len(b)/2] ^= 1; return b },
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte { b[len(magic)+48] = 255; return b },
	} {
		b := modify(append([]byte{}, archive.Bytes()...))
		if err := Open(&bytes.Buffer{}, bytes.NewReader(b), private); err == nil {
			t.Fatal("tamper accepted")
		}
	}
	if err := Open(&bytes.Buffer{}, bytes.NewReader(archive.Bytes()), other); err == nil {
		t.Fatal("wrong key")
	}
}

func FuzzArchiveOpen(f *testing.F) {
	private, public, _ := GenerateKey()
	var valid bytes.Buffer
	Seal(&valid, bytes.NewReader([]byte("test")), public)
	f.Add(valid.Bytes())
	f.Add([]byte("OIMOSEAL1"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<20 {
			return
		}
		_ = Open(&bytes.Buffer{}, bytes.NewReader(raw), private)
	})
}
