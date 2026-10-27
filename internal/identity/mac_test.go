// 用途名と長さ付き項目を結合した独立入力でHMACの互換性と一時確保を検査する。
package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"oimobbs/internal/domain"
	"testing"
)

func referenceMAC(key []byte, name string, fields ...[]byte) domain.Hash {
	raw := binary.BigEndian.AppendUint32(nil, uint32(len(name)))
	raw = append(raw, name...)
	for _, field := range fields {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(field)))
		raw = append(raw, field...)
	}
	h := hmac.New(sha256.New, key)
	h.Write(raw)
	var result domain.Hash
	copy(result[:], h.Sum(nil))
	return result
}

func FuzzMACCompatibility(f *testing.F) {
	f.Add([]byte{}, "", []byte{}, []byte{})
	f.Add([]byte("secret"), "oimo/post-request/v1", []byte("本文"), []byte{0, 255})
	f.Add(make([]byte, 128), "long-key", make([]byte, 256), []byte("suffix"))
	f.Fuzz(func(t *testing.T, key []byte, name string, first, last []byte) {
		for _, fields := range [][][]byte{nil, {first}, {nil, first, {}, last}} {
			if MAC(key, name, fields...) != referenceMAC(key, name, fields...) {
				t.Fatal("HMAC changed")
			}
		}
	})
}

func BenchmarkMACPosting(b *testing.B) {
	key := make([]byte, 32)
	fields := make([][]byte, 24)
	for i := range fields {
		fields[i] = []byte("posting-field")
	}
	b.ReportAllocs()
	for b.Loop() {
		MAC(key, "oimo/post-request/v1", fields...)
	}
}
