// 専ブラとWebの一回同意・再送・耐久保存を実HTTPで検証する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
)

func TestLegacyVerifiedCookieSkipsContentConfirmation(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() { repo.Close() }()
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer server.Close()
	headers := http.Header{"User-Agent": {"Monazilla/1.00 (2chMate/0.8 Android)"}}
	posted := func(body string) bool {
		decoded, err := textcodec.Decode([]byte(body))
		return err == nil && strings.Contains(decoded, "書きこみが終わりました。") && !strings.Contains(body, "2ch_X:cookie")
	}
	fields := url.Values{"bbs": {"news"}, "subject": {"専ブラ試験"}, "MESSAGE": {"最初の本文"}, "FROM": {"名前"}, "mail": {"sage"}}
	res, body := request("POST", "/test/bbs.cgi", fields, headers)
	if res.StatusCode != 200 || !strings.Contains(body, "2ch_X:cookie") || cookies["oimo_anon"] == nil {
		t.Fatal("initial cookie exchange", res.StatusCode, body)
	}
	if len(repo.posting[owner].threads) != 0 {
		t.Fatal("posted without returning anonymous cookie")
	}
	res, body = request("POST", "/test/bbs.cgi", fields, headers)
	if res.StatusCode != 200 || !posted(body) {
		t.Fatal("create asked for content confirmation", res.StatusCode, body)
	}
	for _, cookie := range res.Cookies() {
		if cookie.Name == "oimo_confirm" {
			t.Fatal("issued content confirmation cookie")
		}
	}
	var key uint64
	for candidate := range repo.posting[owner].threads {
		key = candidate
	}
	for i := 1; i <= 2; i++ {
		fields.Set("key", fmt.Sprint(key))
		fields.Del("subject")
		fields.Set("MESSAGE", fmt.Sprintf("本文の違う返信%d", i))
		res, body = request("POST", "/test/bbs.cgi", fields, headers)
		if res.StatusCode != 200 || !posted(body) {
			t.Fatal("reply asked for content confirmation", res.StatusCode, body)
		}
	}
	snapshot, err := repo.Thread(t.Context(), owner, key)
	if err != nil || snapshot.PostCount != 3 {
		t.Fatal("posts not persisted", snapshot, err)
	}
	_, dat := request("GET", fmt.Sprintf("/news/dat/%d.dat", key), nil)
	// Webも同じCookieの規約同意を共有する。
	_, page := request("GET", fmt.Sprintf("/web/post?bbs=news&key=%d", key), nil)
	web := pageFields(page)
	web.Set("MESSAGE", "Webの確認前本文")
	res, page = request("POST", "/web/post?bbs=news", web, headers)
	if res.StatusCode != 303 {
		t.Fatal("Web repeated consent", res.StatusCode, page)
	}
	snapshot, err = repo.Thread(t.Context(), owner, key)
	if err != nil || snapshot.PostCount != 4 {
		t.Fatal("Web post not saved", snapshot, err)
	}
	_, dat = request("GET", fmt.Sprintf("/news/dat/%d.dat", key), nil)
	// 専ブラの受理済み再送は一件のまま返る。
	res, body = request("POST", "/test/bbs.cgi", fields, headers)
	if res.StatusCode != 200 || !posted(body) {
		t.Fatal("retry", res.StatusCode, body)
	}
	_, retriedDAT := request("GET", fmt.Sprintf("/news/dat/%d.dat", key), nil)
	if dat != retriedDAT {
		t.Fatal("retry duplicated post")
	}
	server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	snapshot, err = repo.Thread(t.Context(), owner, key)
	if err != nil || snapshot.PostCount != 4 {
		t.Fatal("restart lost posts", snapshot, err)
	}
}
