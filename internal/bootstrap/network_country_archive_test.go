// 国表archiveの破損・展開上限・国/family矛盾を並列解析でも拒否する。
package bootstrap

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"strings"
	"testing"
)

type countryArchiveFile struct{ name, body string }

func countryArchiveFixture(t testing.TB, files []countryArchiveFile, tail int) []byte {
	t.Helper()
	var out bytes.Buffer
	z := gzip.NewWriter(&out)
	tw := tar.NewWriter(z)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Size: int64(len(f.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	block := make([]byte, 4096)
	for tail > 0 {
		n := min(tail, len(block))
		if _, err := z.Write(block[:n]); err != nil {
			t.Fatal(err)
		}
		tail -= n
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func TestCountryArchiveBounds(t *testing.T) {
	jp := countryArchiveFile{"fixture/country/jp/aggregated.json", `{"countryCode":"JP","prefixes":{"ipv4":["1.1.0.0/16"],"ipv6":[]}}`}
	us := countryArchiveFile{"fixture/country/us/aggregated.json", `{"countryCode":"US","prefixes":{"ipv4":[],"ipv6":["2600::/32"]}}`}
	valid := countryArchiveFixture(t, []countryArchiveFile{jp, us}, 0)
	if rows, err := parseCountryArchive(t.Context(), valid); err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	for _, tc := range []struct {
		name  string
		files []countryArchiveFile
		tail  int
	}{
		{"duplicate", []countryArchiveFile{jp, us, jp}, 0},
		{"mismatch", []countryArchiveFile{jp, {us.name, strings.Replace(us.body, "US", "DE", 1)}}, 0},
		{"hostbits", []countryArchiveFile{{jp.name, strings.Replace(jp.body, "1.1.0.0/16", "1.1.0.1/16", 1)}, us}, 0},
		{"family", []countryArchiveFile{{jp.name, strings.Replace(jp.body, "1.1.0.0/16", "2400::/32", 1)}, us}, 0},
		{"duplicate_json", []countryArchiveFile{{jp.name, strings.Replace(jp.body, `"countryCode":"JP"`, `"countryCode":"JP","countryCode":"JP"`, 1)}, us}, 0},
		{"post_tar_bomb", []countryArchiveFile{jp, us}, 33 << 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCountryArchive(t.Context(), countryArchiveFixture(t, tc.files, tc.tail)); err == nil {
				t.Fatal("不正archiveを受理した")
			}
		})
	}
	valid[len(valid)-8] ^= 1
	if _, err := parseCountryArchive(t.Context(), valid); err == nil {
		t.Fatal("CRC破損を受理した")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := parseCountryArchive(ctx, countryArchiveFixture(t, []countryArchiveFile{jp, us}, 0)); err != context.Canceled {
		t.Fatal("取消を無視した", err)
	}
}
func TestCountryArchiveTotalRowLimit(t *testing.T) {
	files := []countryArchiveFile{}
	for _, code := range []string{"AA", "AB", "AC", "AD", "AE"} {
		files = append(files, countryArchiveFile{"fixture/country/" + strings.ToLower(code) + "/aggregated.json", fmt.Sprintf(`{"countryCode":%q,"prefixes":{"ipv4":[%s"1.0.0.0/8"],"ipv6":[]}}`, code, strings.Repeat(`"1.0.0.0/8",`, 60000))})
	}
	if _, err := parseCountryArchive(t.Context(), countryArchiveFixture(t, files, 0)); err == nil {
		t.Fatal("総件数上限を超えた")
	}
}
