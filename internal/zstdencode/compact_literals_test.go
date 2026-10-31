// 配信用literalの短いヘッダーと単一streamを独立復号器で確認する。
package zstdencode

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstddecode"
	"testing"
)

// TestCompactHTTPLiterals は長さの境界で保存用より大きくならず、両復号器で元に戻ることを検査する。
func TestCompactHTTPLiterals(t *testing.T) {
	random := rand.New(rand.NewPCG(313, 71))
	var compactWork, archiveWork entropyWork
	for _, size := range []int{0, 1, 31, 32, 63, 64, 127, 128, 255, 1023, 1024, 4095, 4096, 16383, 16384, blockLimit} {
		for _, alphabet := range []int{3, 256} {
			t.Run(fmt.Sprintf("%d/%d", size, alphabet), func(t *testing.T) {
				raw := make([]byte, size)
				for i := range raw {
					raw[i] = byte(random.IntN(alphabet))
				}
				compact := encodeHTTPLiterals(raw, nil, &compactWork)
				archive := encodeLiterals(raw, nil, &archiveWork)
				if len(compact) > len(archive) {
					t.Fatalf("literal size increased: %d > %d", len(compact), len(archive))
				}
				if size >= 128 && size < 1024 && alphabet == 3 && compact[0]&15 != 2 {
					t.Fatal("short Huffman data requires one stream", compact[0])
				}
				payload := append(compact, 0)
				kind := uint32(2)
				if len(payload) >= size {
					payload, kind = raw, 0
				}
				header := uint32(len(payload))<<3 | kind<<1 | 1
				frame := append(frameHeader(nil, uint64(size)), byte(header), byte(header>>8), byte(header>>16))
				frame = append(frame, payload...)
				decoded, err := testutil.DecodeZstd(frame)
				if err != nil || !bytes.Equal(raw, decoded) {
					t.Fatal("independent decode", err)
				}
				decoded, err = zstddecode.Decode(frame, size)
				if err != nil || !bytes.Equal(raw, decoded) {
					t.Fatal("product decode", err)
				}
			})
		}
	}
}
