// 公開HTTPで取得した同じ本文を使い、圧縮率・生成時間・確保量を比較する。
package zstdencode

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/testutil"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkHTTPCorpus はOIMO_ZSTD_HTTP_CORPUSのresults.jsonと保存本文を測定する。
// 保持済み結果の再送ではなく、一つの再利用workerによる毎回の圧縮を計時する。
func BenchmarkHTTPCorpus(b *testing.B) {
	root := os.Getenv("OIMO_ZSTD_HTTP_CORPUS")
	if root == "" {
		b.Skip("OIMO_ZSTD_HTTP_CORPUS must point to captured HTTP bodies")
	}
	raw, err := os.ReadFile(filepath.Join(root, "results.json"))
	if err != nil {
		b.Fatal(err)
	}
	var manifest struct {
		Rows []struct {
			Label string `json:"label"`
		} `json:"rows"`
	}
	if err = json.Unmarshal(raw, &manifest); err != nil {
		b.Fatal(err)
	}
	for _, row := range manifest.Rows {
		body, err := os.ReadFile(filepath.Join(root, row.Label+"-identity.body"))
		if err != nil {
			b.Fatal(err)
		}
		b.Run(row.Label, func(b *testing.B) {
			var encoder Encoder
			encoded := encoder.Encode(body)
			decoded, err := testutil.DecodeZstd(encoded)
			if err != nil || !bytes.Equal(decoded, body) {
				b.Fatal("roundtrip", err)
			}
			cpuBefore, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(body)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				encoder.Encode(body)
			}
			cpuAfter, err := testutil.ProcessCPUTime()
			if err != nil {
				b.Fatal(err)
			}
			b.ReportMetric(float64(cpuAfter-cpuBefore)/float64(b.N), "cpu-ns/op")
			b.ReportMetric(float64(len(encoded)), "encoded-bytes")
		})
	}
}
