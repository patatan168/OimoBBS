// 小さいliteralとASCIIの符号表を、独立復号器と保存用復号器で検査する。
package zstdencode

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstddecode"
	"testing"
)

// TestHuffmanShortASCIIFrames は128〜255byteも圧縮し、既存の復号器で読めることを確認する。
func TestHuffmanShortASCIIFrames(t *testing.T) {
	random := rand.New(rand.NewPCG(113, 51))
	var work entropyWork
	for _, size := range []int{127, 128, 129, 255, 256, 1023, 1024, 16383, 16384} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			raw := make([]byte, size)
			for i := range raw {
				raw[i] = "abc"[random.IntN(3)]
			}
			literals := encodeLiterals(raw, nil, &work)
			if size >= 128 && len(literals) >= len(raw) {
				t.Fatal("short literal compression lost", size, len(literals))
			}
			payload := append(literals, 0)
			kind := uint32(2)
			if len(payload) >= size {
				payload, kind = raw, 0
			}
			header := uint32(len(payload))<<3 | kind<<1 | 1
			frame := append(frameHeader(nil, uint64(size)), byte(header), byte(header>>8), byte(header>>16))
			frame = append(frame, payload...)
			independent, err := testutil.DecodeZstd(frame)
			if err != nil || !bytes.Equal(independent, raw) {
				t.Fatal("independent literal decode", err)
			}
			stored, err := zstddecode.Decode(frame, len(raw))
			if err != nil || !bytes.Equal(stored, raw) {
				t.Fatal("stored literal decode", err)
			}
		})
	}
}

// TestHuffmanASCIIWeightHeader はASCII表の未使用weightも圧縮し、短い直接表は維持する。
func TestHuffmanASCIIWeightHeader(t *testing.T) {
	random := rand.New(rand.NewPCG(317, 93))
	raw := make([]byte, 8192)
	for i := range raw {
		raw[i] = byte(32 + random.IntN(95))
	}
	var work entropyWork
	header, _ := huffmanDescription(raw, &work)
	if len(header) == 0 || header[0] >= 128 || len(header) >= 64 {
		t.Fatal("ASCII weight header was not compacted", len(header))
	}
	header, _ = huffmanDescription([]byte{0, 1, 2, 3, 0, 1, 2, 0, 1, 0}, &work)
	if len(header) == 0 || header[0] < 128 {
		t.Fatal("short direct weight header lost")
	}
}
