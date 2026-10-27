// 実ChromiumのURL解釈、Unicode公式のNFC例、任意入力の有界性を独立に照合する。
package urlhost

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestHTTPChromiumHostVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/browser_hosts.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Input string
		Host  *string
	}
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		t.Run(row.Input, func(t *testing.T) {
			host, ok := HTTP(row.Input)
			if row.Host == nil {
				if ok {
					t.Fatalf("browser rejects host, got %q", host)
				}
			} else if !ok || host != *row.Host {
				t.Fatalf("got %q,%t want %q", host, ok, *row.Host)
			}
		})
	}
}

// TestUnicodeIDNAValidVectors は公式の正常な非移行変換例を全件照合する。
// 異常入力の汎用IDNA検査器は公開せず、URLとしての拒否はChromiumの宛先例で別に検査する。
func TestUnicodeIDNAValidVectors(t *testing.T) {
	directory := os.Getenv("OIMO_UNICODE_CONFORMANCE_SOURCES")
	if directory == "" {
		t.Skip("OIMO_UNICODE_CONFORMANCE_SOURCESで固定Unicode原本との全件照合を有効化")
	}
	file, err := os.Open(filepath.Join(directory, "IdnaTestV2.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	escapes := regexp.MustCompile(`\\(?:u([0-9a-fA-F]{4})|x\{([0-9a-fA-F]+)\})`)
	decode := func(raw string) string {
		if raw == `""` {
			return ""
		}
		return escapes.ReplaceAllStringFunc(raw, func(raw string) string {
			parts := escapes.FindStringSubmatch(raw)
			value := parts[1] + parts[2]
			n, e := strconv.ParseUint(value, 16, 32)
			if e != nil {
				t.Fatal(e)
			}
			return string(rune(n))
		})
	}
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(strings.Split(scanner.Text(), "#")[0])
		if line == "" {
			continue
		}
		fields := strings.Split(line, ";")
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		status := fields[4]
		if status == "" {
			status = fields[2]
		}
		if status != "" && status != "[]" {
			continue
		}
		unicode := fields[1]
		if unicode == "" {
			unicode = fields[0]
		}
		want := fields[3]
		if want == "" {
			want = unicode
		}
		want = decode(want)
		if want == "" || forbidden(want) {
			continue
		}
		input := decode(fields[0])
		got, ok := asciiDomain(input)
		if !ok || got != want {
			t.Fatalf("IDNA %q: got %q,%t want %q", input, got, ok, want)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("checked %d valid Unicode IDNA vectors", count)
}

func TestUnicodeNFCConformance(t *testing.T) {
	directory := os.Getenv("OIMO_UNICODE_CONFORMANCE_SOURCES")
	if directory == "" {
		t.Skip("OIMO_UNICODE_CONFORMANCE_SOURCESで固定Unicode原本との全件照合を有効化")
	}
	file, err := os.Open(filepath.Join(directory, "NormalizationTest.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(strings.Split(scanner.Text(), "#")[0])
		if line == "" || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Split(line, ";")
		values := make([][]rune, 5)
		for i := range values {
			for _, code := range strings.Fields(fields[i]) {
				n, e := strconv.ParseUint(code, 16, 32)
				if e != nil {
					t.Fatal(e)
				}
				values[i] = append(values[i], rune(n))
			}
		}
		for i, v := range values {
			want := values[1]
			if i >= 3 {
				want = values[3]
			}
			if got := normalizeNFC(v); string(got) != string(want) {
				t.Fatalf("NFC vector %d column %d got %U want %U", count, i, got, want)
			}
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("checked %d Unicode NFC vectors", count)
}

func FuzzHTTPHost(f *testing.F) {
	for _, raw := range []string{"https://example。test/", "http://0xffffffff/", "https://e\u0301.test/", "https://%ff.test/", "https://a@b/"} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 8192 {
			t.Skip()
		}
		host, ok := HTTP(raw)
		if !ok {
			return
		}
		if host != strings.ToLower(host) || forbidden(host) && !strings.HasPrefix(host, "[") {
			t.Fatalf("invalid normalized host %q", host)
		}
		for _, r := range host {
			if r >= 128 {
				t.Fatalf("non-ASCII host %q", host)
			}
		}
	})
}
