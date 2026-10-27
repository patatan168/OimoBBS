// 実データの圧縮レベルを比較する明示実行専用の診断。
package bootstrap

import (
	"bytes"
	"compress/gzip"
	"oimobbs/internal/zstddecode"
	"oimobbs/internal/zstdencode"
	"testing"
	"time"
)

func TestNetworkCompressionDiagnostic(t *testing.T) {
	client := networkFixtureClient(t)
	value, err := fetchCountries(t.Context(), client)
	if err != nil {
		t.Fatal(err)
	}
	body, err := decompressNetworkData(value, countryUnpackedLimit)
	if err != nil {
		t.Fatal(err)
	}
	for _, level := range []int{1, 4, 6, 9} {
		t.Run(string(rune('0'+level)), func(t *testing.T) {
			var out bytes.Buffer
			z, _ := gzip.NewWriterLevel(&out, level)
			z.Write(body)
			z.Close()
			t.Logf("level=%d size=%d", level, out.Len())
		})
	}
	for _, width := range []int{0, 4, 5, 6, 7} {
		var encoder zstdencode.Encoder
		start := time.Now()
		frame, e := encoder.EncodeBestArchive(body, []zstdencode.ArchiveOptions{{HashBytes: width, AccuracyLog: 9}})
		elapsed := time.Since(start)
		decoded, de := zstddecode.DecodeBounded(frame, len(body), countryUnpackedLimit)
		if e != nil || de != nil || !bytes.Equal(decoded, body) {
			t.Fatal(e, de)
		}
		t.Logf("zstd hash=%d size=%d elapsed=%s", width, len(frame), elapsed)
	}

}
