// HTTP判断fixture、専ブラフォーム、DAT安全化を実装へ適用する。
package compat

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"oimobbs/internal/textcodec"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHTTPFixture(t *testing.T) {
	b, e := os.ReadFile("../../docs/design/fixtures/http-decisions.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Cases []struct {
			ID      string `json:"id"`
			Request struct {
				Method   string `json:"method"`
				Length   int    `json:"length"`
				Accept   string `json:"accept"`
				Range    string `json:"range"`
				IfMatch  string `json:"if_match"`
				IfNone   string `json:"if_none_match"`
				IfRange  string `json:"if_range"`
				Disabled bool   `json:"legacy_range_disabled"`
				Public   string `json:"public_state"`
			} `json:"request"`
			Expected struct {
				Status         int    `json:"status"`
				Representation string `json:"representation"`
				Range          []int  `json:"range"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			if c.Request.Public != "visible" {
				t.Skip("public state gate belongs to application")
			}
			r := httptest.NewRequest(c.Request.Method, "http://localhost/dat", nil)
			for k, v := range map[string]string{"Accept-Encoding": c.Request.Accept, "Range": c.Request.Range, "If-Match": c.Request.IfMatch, "If-None-Match": c.Request.IfNone, "If-Range": c.Request.IfRange} {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			ServeDAT(w, r, Representation{DAT: bytes.Repeat([]byte("a"), c.Request.Length), ETagIdentity: `"identity"`, ETagGzip: `"gzip"`, LegacyRangeDisabled: c.Request.Disabled})
			if w.Code != c.Expected.Status {
				t.Fatalf("got %d want %d", w.Code, c.Expected.Status)
			}
			if c.Request.Method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD body")
			}
			if w.Code == 304 && w.Header().Get("Content-Length") != "" {
				t.Fatal("304 length")
			}
			if w.Code == 206 && len(c.Expected.Range) == 2 && w.Body.Len() != c.Expected.Range[1]-c.Expected.Range[0]+1 {
				t.Fatal("range length")
			}
			if w.Header().Get("Content-Encoding") == "gzip" && w.Code == 200 && c.Request.Method != "HEAD" {
				g, e := gzip.NewReader(w.Body)
				if e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(g)
				if e != nil || len(b) != c.Request.Length {
					t.Fatal("gzip", e)
				}
			}
		})
	}
}
func TestFormAndDAT(t *testing.T) {
	f, e := ParseForm([]byte("bbs=test&FROM=%96%bc%96%b3%82%b5&MESSAGE=%82%a0%26%3D%2B+"), "application/x-www-form-urlencoded", false)
	if e != nil || f["MESSAGE"] != "あ&=+ " {
		t.Fatal(f, e)
	}
	for _, s := range []string{"bbs=a&bbs=b", "FROM=%81", "MESSAGE=%zz", "=x"} {
		if _, e = ParseForm([]byte(s), "application/x-www-form-urlencoded", false); e == nil {
			t.Fatal(s)
		}
	}
	s, e := Normalize("&#38;#60;\r\n😀", true, true)
	if e != nil || s != "&#60;\n😀" {
		t.Fatal(s, e)
	}
	b, e := DAT(domain.Post{Number: 1, Name: "a<>b", Body: "<script>&😀\nnext", Identity: domain.Identity{DateText: "date"}}, "title")
	if e != nil {
		t.Fatal(e)
	}
	decoded, _ := textcodec.Decode(b)
	if strings.Contains(decoded, "<script>") || !strings.Contains(decoded, "&lt;script&gt;&amp;&#128512;<br>next") || strings.Count(decoded, "<>") != 4 {
		t.Fatal(decoded)
	}
}
func FuzzForm(f *testing.F) {
	f.Add([]byte("bbs=test&MESSAGE=a"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseForm(b, "application/x-www-form-urlencoded", false) })
}
func FuzzRange(f *testing.F) {
	f.Add("bytes=1-", uint64(10))
	f.Fuzz(func(t *testing.T, s string, n uint64) {
		r, v, ok := ParseRange(s, n)
		if v && ok && (r.Start > r.End || r.End >= n) {
			t.Fatal(r, n)
		}
	})
}

func TestRepeatedAcceptEncoding(t *testing.T) {
	r := httptest.NewRequest("GET", "http://localhost/dat", nil)
	r.Header.Set("Range", "bytes=1-")
	r.Header.Set("Accept-Encoding", "identity, identity")
	w := httptest.NewRecorder()
	ServeDAT(w, r, Representation{DAT: []byte("abc"), ETagIdentity: `"identity"`})
	if w.Code != 206 || w.Body.String() != "bc" {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestSelection(t *testing.T) {
	for _, v := range []struct {
		Input       string
		Count, Page int
		Want        []int
	}{{"2-3", 10, 1, []int{1, 2, 3}}, {"2-3n", 10, 1, []int{2, 3}}, {"l2", 10, 1, []int{1, 9, 10}}, {"-2n", 10, 1, []int{1, 2}}, {"200-500", 500, 2, appendRange(399, 500)}} {
		got, e := SelectPosts(v.Input, v.Count, v.Page)
		if e != nil || !slices.Equal(got, v.Want) {
			t.Fatalf("%s: %v %v", v.Input, got, e)
		}
	}
	for _, s := range []string{"0", "2-1", "l1001", "-", "1--2", "9999999999999999999999", "1nn"} {
		if _, e := SelectPosts(s, 10, 1); e == nil {
			t.Fatal(s)
		}
	}
}
func appendRange(first, last int) []int {
	var result []int
	for n := first; n <= last; n++ {
		result = append(result, n)
	}
	return result
}

// TestCapDATName は通常名・トリップをキャップ名へ併記せず、旧DATも正確に再現することを確認する。
func TestCapDATName(t *testing.T) {
	for _, name := range []string{"名無しさん", "入力名", ""} {
		p := domain.Post{Number: 1, Name: name, Identity: domain.Identity{Trip: "trip", Cap: "<運営>", DateText: "date", ID: "CAP_USER"}, Body: "本文"}
		raw, e := DAT(p, "題名")
		if e != nil {
			t.Fatal(e)
		}
		dat, e := textcodec.Decode(raw)
		if e != nil || !strings.HasPrefix(dat, "&lt;運営&gt; ★<>") || strings.Contains(dat, "trip") || strings.Contains(dat, "名無しさん") {
			t.Fatal("cap name", dat, e)
		}
		raw, e = LegacyDAT(p, "題名")
		if e != nil {
			t.Fatal(e)
		}
		dat, e = textcodec.Decode(raw)
		if e != nil || !strings.HasPrefix(dat, escape(name)+" ◆trip &lt;運営&gt; ★<>") {
			t.Fatal("legacy cap", dat, e)
		}
	}
	ordinary := domain.Post{Name: "名無しさん", Identity: domain.Identity{Trip: "trip"}}
	current, _ := DAT(ordinary, "")
	legacy, _ := LegacyDAT(ordinary, "")
	if !bytes.Equal(current, legacy) {
		t.Fatal("anonymous display changed")
	}
}

// TestExactDateConditional は日付再取得の等号を、安全な最終更新秒だけに限定する。
func TestExactDateConditional(t *testing.T) {
	modified := time.Unix(1800000000, 500000000)
	for _, tc := range []struct {
		name        string
		exact, safe bool
		date        time.Time
		status      int
	}{
		{"unique second", true, true, modified, 304},
		{"multiple versions in same second", false, true, modified, 200},
		{"older cached version", true, true, modified.Add(-time.Second), 200},
		{"unsafe clock or redaction", true, false, modified, 200},
		{"future conditional", true, true, modified.Add(3 * time.Second), 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := Representation{DAT: []byte("unchanged"), ETagIdentity: `"i"`, Modified: modified, Now: modified.Add(2 * time.Second), DateSafe: tc.safe, DateExact: tc.exact}
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("If-Modified-Since", tc.date.UTC().Format(http.TimeFormat))
			w := httptest.NewRecorder()
			ServeDAT(w, r, p)
			if w.Code != tc.status || tc.status == 304 && w.Body.Len() != 0 {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}
