// ヘッダーの構文・件数・UA長と宣言本文長を、本文を読まずに検査する境界を確認する。
package waf

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInspectHeaderControlBytes(t *testing.T) {
	for _, name := range []string{"User-Agent", "X-Test", "Cookie", "Authorization"} {
		for ch := 0; ch < 128; ch++ {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header[name] = []string{"aaa" + string(byte(ch)) + "bbb"}
			got := Inspect(r)
			forbidden := ch < 32 && ch != '\t' || ch == 127
			if forbidden && got != "header_control" || !forbidden && got != "" {
				t.Fatalf("%s byte=%02x: %q", name, ch, got)
			}
		}
	}
	for _, value := range []string{"Monazilla/1.00 日本語", "opaque\x80\xff", "a\\r\\nHost: example.invalid"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Test", value)
		if got := Inspect(r); got != "" {
			t.Fatal("normal opaque field rejected", got)
		}
	}
}

func TestInspectUserAgentAndFieldLimits(t *testing.T) {
	for _, n := range []int{1024, 1025} {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header["uSeR-aGeNt"] = []string{strings.Repeat("a", n/2), strings.Repeat("b", n-n/2)}
		want := ""
		if n > 1024 {
			want = "user_agent_size"
		}
		if got := Inspect(r); got != want {
			t.Fatal(n, got, want)
		}
	}
	for _, n := range []int{128, 129} {
		r := httptest.NewRequest("GET", "/", nil)
		for i := range n {
			r.Header.Set(fmt.Sprintf("X-%d", i), "")
		}
		want := ""
		if n > 128 {
			want = "header_fields"
		}
		if got := Inspect(r); got != want {
			t.Fatal(n, got, want)
		}
		r.Header = http.Header{"X-Repeated": make([]string, n)}
		if got := Inspect(r); got != want {
			t.Fatal("repeated", n, got, want)
		}
	}
	for _, name := range []string{"Cookie", "Authorization"} {
		for _, extra := range []int{0, 1} {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set(name, strings.Repeat("x", maxInspectionBytes-len(name)+extra))
			want := ""
			if extra != 0 {
				want = "header_size"
			}
			if got := Inspect(r); got != want {
				t.Fatal(name, extra, got, want)
			}
		}
	}
}

func TestInspectContentLengthBoundary(t *testing.T) {
	for _, tc := range []struct {
		raw    string
		length int64
		want   string
	}{
		{"", 0, ""}, {"", -1, ""}, {"", -2, "content_length"}, {"", 256 << 10, ""}, {"", (256 << 10) + 1, "content_length"},
		{"0", 0, ""}, {"0001", 1, ""}, {" 1\t", 1, ""}, {"-1", -1, "content_length"}, {"+1", 1, "content_length"},
		{"999999999999", 999999999999, "content_length"}, {"18446744073709551616", -1, "content_length"}, {"1, 1", 1, "content_length"}, {"2", 1, "content_length"},
	} {
		r := httptest.NewRequest("POST", "/test/bbs.cgi", nil)
		r.ContentLength = tc.length
		if tc.raw != "" {
			r.Header.Set("Content-Length", tc.raw)
		}
		if got := Inspect(r); got != tc.want {
			t.Fatalf("length=%d raw=%q got=%q want=%q", tc.length, tc.raw, got, tc.want)
		}
	}
	r := httptest.NewRequest("POST", "/test/bbs.cgi", nil)
	r.ContentLength = -1
	r.TransferEncoding = []string{"chunked"}
	if got := Inspect(r); got != "" {
		t.Fatal("ordinary chunked body rejected", got)
	}
	r.Header.Set("Content-Length", "0")
	if got := Inspect(r); got != "content_length" {
		t.Fatal("observable framing conflict accepted", got)
	}
	r.TransferEncoding = nil
	r.ContentLength = 0
	r.Header["Content-Length"] = []string{"0", "0"}
	if got := Inspect(r); got != "content_length" {
		t.Fatal("observable repeated length accepted", got)
	}
}

// FuzzInspectHeaderControls は禁止byteを含む値が検査を通らないことを確認する。
func FuzzInspectHeaderControls(f *testing.F) {
	for _, value := range []string{"Monazilla/1.00", "a\x00b", "a\r\nHost: evil", "a\tb", "日本語", "a\x7fb"} {
		f.Add(value)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > maxInspectionBytes-6 {
			t.Skip()
		}
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Test", value)
		got := Inspect(r)
		for i := 0; i < len(value); i++ {
			if value[i] < 32 && value[i] != '\t' || value[i] == 127 {
				if got != "header_control" {
					t.Fatalf("control byte accepted: %q", got)
				}
				break
			}
		}
	})
}
