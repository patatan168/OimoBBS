// 共通専ブラ投稿URLの板解決・確認・再送と公開DATを実HTTPで確認する。
package bootstrap

import (
	"net/http"
	"net/url"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
)

func checkLegacyPosting(t *testing.T, request feedRequest, key string) {
	t.Helper()
	decode := func(body string) string {
		s, e := textcodec.Decode([]byte(body))
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	path := "/test/bbs.cgi?bbs=alpha"
	fields := url.Values{"bbs": {"beta"}, "key": {key}, "FROM": {"専ブラ試験#A"}, "MESSAGE": {"専ブラ返信😀"}, "mail": {"sage"}}
	r, page := request("POST", path, fields)
	if r.StatusCode != 200 || !strings.Contains(decode(page), "書きこみが終わりました。") || strings.Contains(decode(page), "<!-- 2ch_X:cookie -->") {
		t.Fatal("shared consent", r.StatusCode, decode(page))
	}
	for range 2 {
		r, page = request("POST", path, fields)
		if r.StatusCode != 200 || !strings.Contains(decode(page), "書きこみが終わりました。") || !strings.Contains(decode(page), "/beta/"+key+"/2") {
			t.Fatal("post/retry", r.StatusCode, decode(page))
		}
	}
	_, dat := request("GET", "/beta/dat/"+key+".dat", nil)
	if strings.Count(dat, "\n") != 2 || !strings.Contains(decode(dat), "専ブラ返信&#128512;") {
		t.Fatal("wrong DAT", decode(dat))
	}
	r, _ = request("GET", "/test/bbs.cgi", nil)
	if r.StatusCode != 405 || r.Header.Get("Allow") != "POST" {
		t.Fatal("method")
	}
	fields.Set("bbs", "missing")
	r, page = request("POST", "/test/bbs.cgi", fields)
	if r.StatusCode != 200 || !strings.Contains(decode(page), "ERROR:") {
		t.Fatal("unknown board")
	}
	fields["bbs"] = []string{"alpha", "beta"}
	r, _ = request("POST", "/test/bbs.cgi", fields)
	if r.StatusCode != 400 {
		t.Fatal("duplicate board", r.StatusCode)
	}
	fields.Set("bbs", "beta")
	fields.Set("MESSAGE", strings.Repeat("x", 65537))
	r, _ = request("POST", "/test/bbs.cgi", fields)
	if r.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatal("body limit", r.StatusCode)
	}
}
