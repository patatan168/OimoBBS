// 大きい高エントロピーDATの圧縮・展開を、同じ入力と保存CRC検査で比較する。
package store

import (
	"bytes"
	"fmt"
	"oimobbs/internal/testutil"
	"slices"
	"testing"
)

// BenchmarkLargeEntropyDAT は入力準備を除き、保存圧縮とCRC付き展開の時間・CPU・確保量を測る。
func BenchmarkLargeEntropyDAT(b *testing.B) {
	inputs := map[string][]byte{"original": testutil.DATFixture("entropy")}
	for _, tc := range []struct {
		kind string
		size int
		seed uint64
	}{{"hex-fields", 256 << 10, 1031}, {"hex-fields", 512 << 10, 2081}, {"hex", 128 << 10, 7}, {"hex", 384 << 10, 23}, {"hex", 512 << 10, 61}, {"hex", 320 << 10, 313}, {"hex", 512 << 10, 271}, {"base64", 512 << 10, 97}, {"base64", 512 << 10, 509}, {"ascii", 512 << 10, 137}} {
		name := fmt.Sprintf("%s-%dk-s%d", tc.kind, tc.size>>10, tc.seed)
		inputs[name] = testutil.EntropyDATFixture(tc.kind, tc.size, tc.seed)
	}
	var names []string
	for name := range inputs {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		raw := inputs[name]
		for _, mode := range []string{"encode", "decode"} {
			b.Run(name+"/"+mode, func(b *testing.B) {
				chunk, err := EncodePackChunk(raw, 9)
				if err != nil {
					b.Fatal(err)
				}
				decoded, err := DecodePackChunk(chunk)
				if err != nil || !bytes.Equal(decoded, raw) {
					b.Fatal("roundtrip", err)
				}
				before, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.SetBytes(int64(len(raw)))
				b.ReportAllocs()
				b.ResetTimer()
				for b.Loop() {
					if mode == "encode" {
						if _, err := EncodePackChunk(raw, 9); err != nil {
							b.Fatal(err)
						}
					} else {
						if _, err := DecodePackChunk(chunk); err != nil {
							b.Fatal(err)
						}
					}
				}
				after, err := testutil.ProcessCPUTime()
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(after-before)/float64(b.N), "cpu-ns/op")
				b.ReportMetric(float64(len(chunk.Stored)), "encoded-bytes")
			})
		}
	}
}
