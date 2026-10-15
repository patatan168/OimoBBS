// 永続投稿から専ブラ用一覧・DATと条件付き差分取得までを実HTTPで確認する。
package bootstrap

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/testutil"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/textcodec"
)

type feedRequest func(string, string, url.Values, ...http.Header) (*http.Response, string)

func checkDedicatedFeeds(t *testing.T, request feedRequest, base, key string) (string, string) {
	t.Helper()
	decode := func(raw string) string {
		t.Helper()
		s, e := textcodec.Decode([]byte(raw))
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	r, body := request("GET", "/bbsmenu.json", nil)
	var menu struct {
		List []struct {
			Name   string `json:"category_name"`
			Boards []struct {
				Name string `json:"board_name"`
				URL  string `json:"url"`
			} `json:"category_content"`
		} `json:"menu_list"`
	}
	if r.StatusCode != 200 || json.Unmarshal([]byte(body), &menu) != nil || len(menu.List) != 1 || len(menu.List[0].Boards) != 2 || menu.List[0].Boards[0].URL != base+"/alpha/" || menu.List[0].Boards[0].Name != "アルファ板" {
		t.Fatal("menu", body)
	}
	_, body = request("GET", "/bbsmenu.html", nil)
	if !strings.Contains(decode(body), `href="`+base+`/beta/"`) {
		t.Fatal("HTML menu", decode(body))
	}
	_, body = request("GET", "/alpha/SETTING.TXT", nil)
	if !strings.Contains(decode(body), "BBS_TITLE=アルファ板\n") || !strings.Contains(decode(body), "BBS_MESSAGE_COUNT=4096\n") {
		t.Fatal("settings", decode(body))
	}
	_, body = request("GET", "/alpha/subject.txt", nil)
	if !strings.HasPrefix(decode(body), key+".dat<>alpha-first (3)\n") || strings.Contains(body, "beta-only") {
		t.Fatal("subject", decode(body))
	}
	for _, path := range []string{"/bbsmenu.json", "/bbsmenu.html", "/alpha/SETTING.TXT", "/alpha/head.txt", "/alpha/subject.txt", "/", "/alpha/", "/test/read.cgi/alpha/" + key + "/"} {
		g, b := request("GET", path, nil, http.Header{"Accept-Encoding": {"identity"}})
		h, hb := request("HEAD", path, nil)
		if g.StatusCode != 200 || h.StatusCode != 200 || hb != "" || h.ContentLength != int64(len(b)) {
			t.Fatal("feed HEAD", path)
		}
		if strings.HasSuffix(path, ".txt") || strings.HasSuffix(path, ".TXT") || strings.HasSuffix(path, ".json") {
			checkPublicDataHeaders(t, g.Header)
		} else if !strings.Contains(g.Header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatal("HTML CSP changed", path)
		}
		etag := g.Header.Get("ETag")
		cached, cachedBody := request("GET", path, nil, http.Header{"Accept-Encoding": {"identity"}, "If-None-Match": {etag}})
		if etag == "" || cached.StatusCode != 304 || cachedBody != "" || cached.Header.Get("Content-Length") != "" {
			t.Fatal("feed conditional", path, cached.StatusCode)
		}
		for _, coding := range []string{"gzip", "zstd"} {
			zipped, compressed := request("GET", path, nil, http.Header{"Accept-Encoding": {coding + ", identity;q=0"}, "Range": {"bytes=1-"}})
			zr, err := compressedFeedReader(coding, compressed)
			if err != nil {
				t.Fatal(path, err)
			}
			decoded, err := io.ReadAll(zr)
			zr.Close()
			if err != nil || zipped.StatusCode != 200 || string(decoded) != b || zipped.Header.Get("ETag") == etag || zipped.Header.Get("Content-Range") != "" {
				t.Fatal("feed gzip", path, err)
			}
			cached, cachedBody = request("GET", path, nil, http.Header{"Accept-Encoding": {coding + ", identity;q=0"}, "If-None-Match": {zipped.Header.Get("ETag")}})
			if cached.StatusCode != 304 || cachedBody != "" {
				t.Fatal("gzip feed conditional", path)
			}
			zh, zhb := request("HEAD", path, nil, http.Header{"Accept-Encoding": {coding + ", identity;q=0"}})
			if zh.StatusCode != 200 || zhb != "" || zh.Header.Get("Content-Encoding") != coding || zh.Header.Get("Content-Length") != "" {
				t.Fatal("feed gzip HEAD", path)
			}
		}
		p, _ := request("POST", path, nil)
		if p.StatusCode != 405 {
			t.Fatal("feed method", path, p.StatusCode)
		}
	}
	path := "/alpha/dat/" + key + ".dat"
	r, dat := request("GET", path, nil, http.Header{"Accept-Encoding": {"identity"}})
	checkPublicDataHeaders(t, r.Header)
	tag := r.Header.Get("ETag")
	if r.StatusCode != 200 || tag == "" || !strings.HasSuffix(tag, `-1-3-identity"`) || !strings.Contains(decode(dat), "sage reply") || strings.Contains(dat, "127.0.0.1") {
		t.Fatal("DAT", r.StatusCode, r.Header, decode(dat))
	}
	modified := r.Header.Get("Last-Modified")
	at, e := http.ParseTime(modified)
	if e != nil {
		t.Fatal("missing Last-Modified", modified)
	}
	for _, tc := range []struct {
		date   string
		status int
	}{
		{modified, 200}, {at.Add(time.Second).Format(http.TimeFormat), 304},
	} {
		got, _ := request("GET", path, nil, http.Header{"Accept-Encoding": {"identity"}, "If-Modified-Since": {tc.date}})
		if got.StatusCode != tc.status {
			t.Fatal("date condition", tc, got.StatusCode)
		}
	}
	for _, tc := range []struct {
		headers http.Header
		status  int
		body    string
	}{
		{http.Header{"If-None-Match": {tag}}, 304, ""},
		{http.Header{"If-Match": {`"old"`}}, 412, ""},
		{http.Header{"Range": {"bytes=5-"}}, 206, dat[5:]},
		{http.Header{"Range": {"bytes=5-"}, "If-Range": {tag}}, 206, dat[5:]},
		{http.Header{"Range": {"bytes=5-"}, "If-Range": {`"old"`}}, 200, dat},
		{http.Header{"Range": {"bytes=" + strconv.Itoa(len(dat)) + "-"}}, 416, ""},
		{http.Header{"Accept-Encoding": {"identity;q=0, gzip;q=0"}}, 406, ""},
	} {
		if tc.headers.Get("Accept-Encoding") == "" {
			tc.headers.Set("Accept-Encoding", "identity")
		}
		got, b := request("GET", path, nil, tc.headers)
		if got.StatusCode != tc.status || b != tc.body {
			t.Fatal("DAT conditional", tc.headers, got.StatusCode, b)
		}
		if tc.status == 304 && got.Header.Get("Content-Length") != "" {
			t.Fatal("304 length")
		}
	}
	h, hb := request("HEAD", path, nil, http.Header{"Range": {"bytes=5-"}})
	if h.StatusCode != 200 || hb != "" || h.ContentLength != int64(len(dat)) {
		t.Fatal("DAT HEAD")
	}
	g, compressed := request("GET", path, nil, http.Header{"Accept-Encoding": {"identity;q=0, gzip"}})
	z, e := gzip.NewReader(strings.NewReader(compressed))
	if e != nil {
		t.Fatal(e)
	}
	raw, e := io.ReadAll(z)
	z.Close()
	if e != nil || g.StatusCode != 200 || string(raw) != dat || g.Header.Get("ETag") == tag || g.Header.Get("Content-Encoding") != "gzip" {
		t.Fatal("DAT gzip", e)
	}
	for _, bad := range []string{"/alpha/dat/01.dat", "/alpha/dat/1.dat/extra", "/missing/subject.txt", "/alpha/dat/1.dat.gz"} {
		rr, _ := request("GET", bad, nil)
		if rr.StatusCode != 404 {
			t.Fatal("invalid route", bad, rr.StatusCode)
		}
	}
	return tag, dat
}

// compressedFeedReader は受信表現を独立したdecoderで検査する。
func compressedFeedReader(coding, raw string) (io.ReadCloser, error) {
	switch coding {
	case "gzip":
		return gzip.NewReader(strings.NewReader(raw))
	case "zstd":
		decoded, e := testutil.DecodeZstd([]byte(raw))
		if e != nil {
			return nil, e
		}
		return io.NopCloser(strings.NewReader(string(decoded))), nil

	}
	return nil, fmt.Errorf("unexpected coding %s", coding)
}

// checkPublicDataHeaders は非HTMLの実HTTPでも実行禁止と既存の境界保護を維持することを確認する。
func checkPublicDataHeaders(t *testing.T, headers http.Header) {
	t.Helper()
	old := httptest.NewRecorder()
	postingHeaders(old)
	next := httptest.NewRecorder()
	publicDataHeaders(next)
	policy := headers.Get("Content-Security-Policy")
	if policy != next.Header().Get("Content-Security-Policy") || len(old.Header().Get("Content-Security-Policy"))-len(policy) != 37 || headers.Get("X-Content-Type-Options") != "nosniff" || headers.Get("Referrer-Policy") != "same-origin" {
		t.Fatal("data header protection", headers)
	}
}
