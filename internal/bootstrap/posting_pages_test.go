// JavaScriptなしのフォーム→確認→303を実HTTPで検査する。
package bootstrap

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

var hiddenInput = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

func pageFields(body string) url.Values {
	out := url.Values{}
	for _, m := range hiddenInput.FindAllStringSubmatch(body, -1) {
		out.Set(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return out
}
func TestPostingHTMLRoundTrip(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "画面試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	board, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	observer, e := evidence.NewHTTPObserver(report.SiteID, domain.NewID(), "page-test")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(repo.BoardWebHandler(board.ID, observer))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, fields url.Values) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(fields.Encode()))
		req.Host = "127.0.0.1:9080"
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("Origin", cfg.Public.BaseURL)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		for _, c := range response.Cookies() {
			cookies[c.Name] = c
		}
		cache := "no-store"
		if strings.HasPrefix(path, "/test/read.cgi/") {
			cache = "no-cache"
		}
		if response.Header.Get("Cache-Control") != cache || response.Header.Get("Content-Security-Policy") == "" {
			t.Fatal("missing page protection")
		}
		return response, string(body)
	}
	response, body := request("GET", "/web/post", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "スレッドを立てる") {
		t.Fatal(response.StatusCode, body)
	}
	firstCookie := cookies["oimo_web"].Value
	fields := pageFields(body)
	// 別タブのGETでCookieを替えず、最初のCSRFも引き続き使用できる。
	request("GET", "/web/post", nil)
	if cookies["oimo_web"].Value != firstCookie {
		t.Fatal("another tab replaced CSRF cookie")
	}
	fields.Set("subject", "題<script>alert(1)</script>")
	fields.Set("FROM", "名前#trip-private-secret")
	fields.Set("MESSAGE", "本文<script>alert(2)</script>")
	fields.Set("unknown", "unknown-private-secret")
	response, body = request("POST", "/web/post", fields)
	if response.StatusCode != 200 || !strings.Contains(body, "書き込み確認") || strings.Contains(body, "<script>") || strings.Contains(body, "unknown-private-secret") {
		t.Fatal(response.StatusCode, body)
	}
	beforeForm := strings.SplitN(body, "<form", 2)[0]
	if strings.Contains(beforeForm, "trip-private-secret") {
		t.Fatal("trip secret displayed")
	}
	confirm := pageFields(body)
	if confirm.Get("FROM") != fields.Get("FROM") || confirm.Get("oimo_request_id") != fields.Get("oimo_request_id") {
		t.Fatal("confirmation changed input")
	}
	response, _ = request("POST", "/web/post", confirm)
	location := response.Header.Get("Location")
	if response.StatusCode != 303 || !strings.HasPrefix(location, cfg.Public.BaseURL+"/test/read.cgi/news/") {
		t.Fatal(response.StatusCode, location)
	}
	response, view := request("GET", strings.TrimPrefix(location, cfg.Public.BaseURL), nil)
	if response.StatusCode != 200 || !strings.Contains(view, "返信する") || !strings.Contains(view, "本文&lt;script&gt;") || strings.Contains(view, "trip-private-secret") || strings.Contains(view, "127.0.0.1") {
		t.Fatal("unsafe or missing thread view", response.StatusCode, view)
	}
	head, _ := request("HEAD", strings.TrimPrefix(location, cfg.Public.BaseURL), nil)
	if head.StatusCode != 200 || head.ContentLength != int64(len(view)) {
		t.Fatal("HEAD mismatch")
	}
	response, _ = request("POST", "/web/post", confirm)
	if response.StatusCode != 303 || response.Header.Get("Location") != location {
		t.Fatal("duplicate has different destination")
	}
	parts := strings.Split(strings.TrimPrefix(location, cfg.Public.BaseURL+"/test/read.cgi/news/"), "/")
	response, body = request("GET", "/web/post?key="+parts[0], nil)
	if response.StatusCode != 200 || !strings.Contains(body, "返信する") {
		t.Fatal(response.StatusCode, body)
	}
	reply := pageFields(body)
	reply.Set("MESSAGE", "返信です")
	response, body = request("POST", "/web/post", reply)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	response, _ = request("POST", "/web/post", pageFields(body))
	if response.StatusCode != 303 || !strings.HasSuffix(response.Header.Get("Location"), "/2") {
		t.Fatal("reply not committed")
	}
	response, body = request("GET", "/web/post", nil)
	invalid := pageFields(body)
	invalid.Set("subject", "入力保持")
	invalid.Set("FROM", "名前#must-not-display")
	invalid.Set("mail", "#cap:id:cap-must-not-display")
	invalid.Set("MESSAGE", "訂正する本文")
	response, body = request("POST", "/web/post", invalid)
	if response.StatusCode != 422 || !strings.Contains(body, "訂正する本文") || strings.Contains(body, "must-not-display") || pageFields(body).Get("oimo_request_id") == invalid.Get("oimo_request_id") {
		t.Fatal("unsafe error form", response.StatusCode, body)
	}
	response, _ = request("GET", "/web/post?key=1&key=2", nil)
	if response.StatusCode != 400 {
		t.Fatal("duplicate key accepted")
	}
	response, _ = request("DELETE", "/web/post", nil)
	if response.StatusCode != 405 || response.Header.Get("Allow") != "GET, POST" {
		t.Fatal("wrong method accepted")
	}
	// 容量不足でも再送フォームの本文・再送IDを保持し、503と待ち時間を返す。
	response, body = request("GET", "/web/post", nil)
	capacityFields := pageFields(body)
	capacityFields.Set("subject", "容量不足試験")
	capacityFields.Set("MESSAGE", "再送時にも残す本文")
	repo.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 1 << 30}, nil
	}
	response, body = request("POST", "/web/post", capacityFields)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	capacityConfirm := pageFields(body)
	response, body = request("POST", "/web/post", capacityConfirm)
	if response.StatusCode != 503 || response.Header.Get("Retry-After") != "30" || !strings.Contains(body, "容量の回復") || pageFields(body).Get("oimo_request_id") != capacityConfirm.Get("oimo_request_id") || !strings.Contains(body, "再送時にも残す本文") {
		t.Fatal(response.StatusCode, body)
	}
	repo.packSpace = nil
	b := repo.posting[board.ID]
	if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.stopped = true; return nil, nil }); e != nil {
		t.Fatal(e)
	}
	response, body = request("POST", "/web/post", confirm)
	retryFields := pageFields(body)
	if response.StatusCode != 503 || response.Header.Get("Location") != "" || retryFields.Get("oimo_request_id") != confirm.Get("oimo_request_id") || retryFields.Get("FROM") != confirm.Get("FROM") {
		t.Fatal("unavailable writer changed retry input", response.StatusCode)
	}

	key, _ := strconv.ParseUint(parts[0], 10, 64)
	snapshot, e := repo.Thread(context.Background(), board.ID, key)
	if e != nil || snapshot == nil {
		t.Fatal(e)
	}
	originalNow := time.Now()
	for _, at := range []time.Time{time.Unix(0, int64(snapshot.Expires)), originalNow} {
		_, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return at }; return nil, nil })
		if e != nil {
			t.Fatal(e)
		}
		response, body = request("GET", strings.TrimPrefix(location, cfg.Public.BaseURL), nil)
		if response.StatusCode != 410 || strings.Contains(body, "本文") || strings.Contains(body, "trip-private-secret") {
			t.Fatal("expired thread exposed", response.StatusCode, body)
		}
	}

}
