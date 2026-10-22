// 複数板の一覧・投稿振分け・順位・復旧を実HTTPで検査する。
package bootstrap

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSiteWebBoardsAndIsolation(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "掲示板一覧")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { repo.Close() }()
	start := func() *httptest.Server {
		observer, e := evidence.NewHTTPObserver(report.SiteID, domain.NewID(), "site-test")
		if e != nil {
			t.Fatal(e)
		}
		s := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
		s.Config.ConnContext = observer.ConnContext
		s.Start()
		s.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return s
	}
	server := start()
	defer func() { server.Close() }()
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, fields url.Values, headers ...http.Header) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(fields.Encode()))
		req.Host = "127.0.0.1:9080"
		if len(headers) > 0 {
			req.Header = headers[0].Clone()
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("Origin", cfg.Public.BaseURL)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		response, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		raw, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		for _, c := range response.Cookies() {
			cookies[c.Name] = c
		}
		return response, string(raw)
	}
	response, body := request("GET", "/", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "公開されている板がありません") {
		t.Fatal(response.StatusCode, body)
	}
	a, e := repo.CreateBoard(context.Background(), "alpha", "アルファ板")
	if e != nil {
		t.Fatal(e)
	}
	_, e = repo.CreateBoard(context.Background(), "beta", "ベータ板")
	if e != nil {
		t.Fatal(e)
	}
	response, body = request("GET", "/", nil)
	if response.StatusCode != 200 || !strings.Contains(body, `href="/alpha/"`) || !strings.Contains(body, `href="/beta/"`) || strings.Contains(body, "板を追加") {
		t.Fatal(body)
	}
	head, headBody := request("HEAD", "/", nil)
	if head.StatusCode != 200 || headBody != "" || head.ContentLength != int64(len(body)) {
		t.Fatal("HEAD mismatch")
	}
	response, body = request("GET", "/alpha/", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "まだスレッドがありません") {
		t.Fatal(body)
	}
	post := func(slug, key, title, message, mail string) string {
		t.Helper()
		path := "/web/post?bbs=" + slug
		_, page := request("GET", path+"&key="+key, nil)
		fields := pageFields(page)
		if fields.Get("bbs") != slug || !strings.Contains(page, `action="/web/post?bbs=`+slug+`"`) {
			t.Fatal("wrong form board", page)
		}
		fields.Set("MESSAGE", message)
		fields.Set("mail", mail)
		if key == "" {
			fields.Set("subject", title)
		}
		r, page := request("POST", path, fields)
		if r.StatusCode == 200 {
			if !strings.Contains(page, "Cookieと利用規約に同意して書き込む") {
				t.Fatal("consent page", page)
			}
			r, page = request("POST", path, pageFields(page))
		}
		if r.StatusCode != 303 {
			t.Fatal(r.StatusCode, page)
		}
		return r.Header.Get("Location")
	}
	postingTime := time.Now().Add(-2 * time.Second)
	setClock := func(now time.Time) {
		t.Helper()
		// 全板共通の時計逆行境界を検査するため、板ごとの注入時計も揃える。
		for _, b := range repo.posting {
			if _, err := b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return now }; return nil, nil }); err != nil {
				t.Fatal(err)
			}
		}
	}
	setClock(postingTime)
	first := post("alpha", "", "alpha-first", "first body", "")
	post("alpha", "", "alpha-second", "second body", "")
	other := post("beta", "", "beta-only", "beta body", "")
	key := strings.Split(strings.TrimPrefix(first, cfg.Public.BaseURL+"/test/read.cgi/alpha/"), "/")[0]
	_, body = request("GET", "/alpha/", nil)
	if strings.Index(body, "alpha-second") > strings.Index(body, "alpha-first") || strings.Contains(body, "beta-only") {
		t.Fatal("initial order/isolation", body)
	}
	initial, initialDAT := request("GET", "/alpha/dat/"+key+".dat", nil)
	post("alpha", key, "", "sage reply", "sage")
	_, body = request("GET", "/alpha/", nil)
	if strings.Index(body, "alpha-second") > strings.Index(body, "alpha-first") {
		t.Fatal("sage bumped thread", body)
	}
	post("alpha", key, "", "age reply", "")
	_, body = request("GET", "/alpha/", nil)
	if strings.Index(body, "alpha-first") > strings.Index(body, "alpha-second") {
		t.Fatal("age did not bump", body)
	}
	_, body = request("GET", "/beta/", nil)
	if !strings.Contains(body, "beta-only") || strings.Contains(body, "alpha-first") {
		t.Fatal("boards mixed", body)
	}
	_, body = request("GET", strings.TrimPrefix(other, cfg.Public.BaseURL), nil)
	if !strings.Contains(body, "beta body") || strings.Contains(body, "first body") || !strings.Contains(body, "bbs=beta") {
		t.Fatal("wrong thread board", body)
	}
	_, page := request("GET", "/web/post?bbs=alpha", nil)
	wrong := pageFields(page)
	wrong.Set("bbs", "beta")
	wrong.Set("subject", "cross-board")
	wrong.Set("MESSAGE", "must not post")
	response, _ = request("POST", "/web/post?bbs=alpha", wrong)
	if response.StatusCode != 422 {
		t.Fatal("mismatched board accepted")
	}
	for _, tc := range []struct {
		path   string
		status int
	}{{"/web/post", 400}, {"/web/post?bbs=alpha&bbs=beta", 400}, {"/missing/", 404}, {"/admin/boards", 404}, {"/alpha/?page=2", 404}, {"/alpha/index.html", 200}, {"/alpha/subback.html", 200}} {
		r, _ := request("GET", tc.path, nil)
		if r.StatusCode != tc.status {
			t.Fatal(tc, r.StatusCode)
		}
	}
	response, _ = request("POST", "/", url.Values{"board": {"attacker"}})
	if response.StatusCode != 405 {
		t.Fatal("public board mutation accepted")
	}
	checkLegacyPosting(t, request, strings.Split(strings.TrimPrefix(other, cfg.Public.BaseURL+"/test/read.cgi/beta/"), "/")[0])
	setClock(time.Now())
	feedTag, feedDAT := checkDedicatedFeeds(t, request, cfg.Public.BaseURL, key)
	if initial.Header.Get("ETag") == feedTag {
		t.Fatal("reply did not change ETag")
	}
	delta, deltaDAT := request("GET", "/alpha/dat/"+key+".dat", nil, http.Header{"Range": {"bytes=" + strconv.Itoa(len(initialDAT)) + "-"}})
	if delta.StatusCode != 206 || initialDAT+deltaDAT != feedDAT {
		t.Fatal("append Range changed cached prefix")
	}
	if _, err := repo.CreateBoard(context.Background(), "dat", "DATという板"); err != nil {
		t.Fatal(err)
	}
	settings, _ := request("GET", "/dat/SETTING.TXT", nil)
	if settings.StatusCode != 200 {
		t.Fatal("dat board routed as thread")
	}
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	server = start()
	restored, restoredDAT := request("GET", "/alpha/dat/"+key+".dat", nil, http.Header{"Accept-Encoding": {"identity"}})
	if restored.Header.Get("ETag") != feedTag || restoredDAT != feedDAT {
		t.Fatal("DAT changed after recovery")
	}
	_, body = request("GET", "/alpha/", nil)
	if !strings.Contains(body, "alpha-first") || strings.Index(body, "alpha-first") > strings.Index(body, "alpha-second") || strings.Contains(body, "cross-board") {
		t.Fatal("restored list differs", body)
	}
	setClock(postingTime.Add(-time.Hour))
	post("alpha", key, "", "clock reversed reply", "")
	reversed, _ := request("GET", "/alpha/dat/"+key+".dat", nil)
	if reversed.Header.Get("Last-Modified") != "" {
		t.Fatal("unsafe reversed date")
	}
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	server = start()
	reversed, _ = request("GET", "/alpha/dat/"+key+".dat", nil)
	if reversed.Header.Get("Last-Modified") != "" {
		t.Fatal("recovery forgot clock reversal")
	}
	b := repo.posting[a.ID]
	future := time.Now().AddDate(0, 7, 0)
	_, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return future }; return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	_, body = request("GET", "/alpha/", nil)
	if strings.Contains(body, "alpha-first") || !strings.Contains(body, "まだスレッドがありません") {
		t.Fatal("expired thread listed", body)
	}
	expired, _ := request("GET", "/alpha/dat/"+key+".dat", nil, http.Header{"If-None-Match": {reversed.Header.Get("ETag")}})
	if expired.StatusCode != 410 {
		t.Fatal("expired conditional DAT", expired.StatusCode)
	}
	_, subject := request("GET", "/alpha/subject.txt", nil)
	if subject != "" {
		t.Fatal("expired subject", subject)
	}
	_, body = request("GET", "/beta/", nil)
	if !strings.Contains(body, "beta-only") {
		t.Fatal("other board disappeared")
	}
}
