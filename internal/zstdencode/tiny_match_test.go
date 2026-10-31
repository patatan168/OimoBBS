// 追加の短い候補表を使わない配信本文でも、4byte一致を利用できることを確認する。
package zstdencode

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

// TestTinyHTTPFourByteMatch は5byte目が異なる候補を拾い、保存の探索方針は維持する。
func TestTinyHTTPFourByteMatch(t *testing.T) {
	raw := make([]byte, 128)
	rng := rand.New(rand.NewPCG(131, 73))
	for i := range raw {
		raw[i] = byte('!' + rng.IntN(90))
	}
	copy(raw[16:], "ABCDx")
	copy(raw[64:], "ABCDy")
	for _, http := range []bool{false, true} {
		var e Encoder
		e.smallHTTP = http
		hash := longHash(binary.LittleEndian.Uint64(raw[16:]), 0xffffffff)
		e.long[(hash>>16)&((1<<15)-1)] = uint64(hash)<<32 | 17
		e.parse(raw, 64, len(raw), [3]int{1, 4, 8})
		if !http {
			if len(e.coded) != 0 {
				t.Fatal("archive match policy changed")
			}
			continue
		}
		if len(e.coded) != 1 || e.coded[0].symbol[0] != 0 || e.coded[0].symbol[2] != 1 || len(e.literals) != 60 || e.nextRepeats[0] != 48 {
			t.Fatal("four-byte match lost", e.coded, len(e.literals), e.nextRepeats)
		}
	}
}
