// 固定した公開HTTP本文のframeを使い、復号時間と返却配列の確保量を比較する。
package zstddecode

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkHTTPDecodeCorpus はOIMO_ZSTD_DECODE_CORPUSの固定frameを毎回新しい出力へ展開する。
// frame生成・読取り・独立復号確認は計時外とし、キャッシュを使わない。
func BenchmarkHTTPDecodeCorpus(b *testing.B) {
	root := os.Getenv("OIMO_ZSTD_DECODE_CORPUS")
	if root == "" {
		b.Skip("OIMO_ZSTD_DECODE_CORPUS must point to frozen HTTP frames")
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		b.Fatal(err)
	}
	var rows []struct {
		Label string `json:"label"`
	}
	if err = json.Unmarshal(data, &rows); err != nil {
		b.Fatal(err)
	}
	for _, row := range rows {
		frame, err := os.ReadFile(filepath.Join(root, row.Label+".zst"))
		if err != nil {
			b.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(root, row.Label+".raw"))
		if err != nil {
			b.Fatal(err)
		}
		independent, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(raw, independent) {
			b.Fatal(row.Label, "independent decode", err)
		}
		b.Run(row.Label, func(b *testing.B) {
			out, err := Decode(frame, len(raw))
			if err != nil || !bytes.Equal(raw, out) {
				b.Fatal("roundtrip", err)
			}
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				out, err := Decode(frame, len(raw))
				if err != nil || len(out) != len(raw) {
					b.Fatal(err)
				}
			}
			cpuAfter, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
		})
	}
}

// BenchmarkArchiveDecode は保存Level 6と同じ精度8の固定frameを新しい出力へ復号する。
func BenchmarkArchiveDecode(b *testing.B) {
	for _, kind := range []string{"text", "mixed", "entropy"} {
		raw := testutil.DATFixture(kind)
		var encoder zstdencode.Encoder
		frame, err := encoder.EncodeArchive(raw, zstdencode.ArchiveOptions{AccuracyLog: 8})
		if err != nil {
			b.Fatal(err)
		}
		independent, err := testutil.DecodeZstd(frame)
		if err != nil || !bytes.Equal(raw, independent) {
			b.Fatal("independent archive decode", err)
		}
		b.Run(kind, func(b *testing.B) {
			out, err := Decode(frame, len(raw))
			if err != nil || !bytes.Equal(raw, out) {
				b.Fatal("archive roundtrip", err)
			}
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(raw)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				out, err := Decode(frame, len(raw))
				if err != nil || len(out) != len(raw) {
					b.Fatal(err)
				}
			}
			cpuAfter, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
		})
	}
}
