// 同一内容だけのIP/Cookie移動窓、予約取消、HTTP応答、設定保存と復旧を検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
)

func contentTestEntry(at domain.Time, ip, cookie byte) guardEntry {
	return guardEntry{id: domain.NewID(), at: at, content: domain.Hash{9}, contentIP: domain.Hash{ip}, token: domain.Hash{cookie}}
}
func requireContentLimited(t *testing.T, err error, seconds uint64) {
	t.Helper()
	var rate *abuse.RateLimited
	if !errors.As(err, &rate) || rate.RetryAfter != seconds {
		t.Fatalf("want wait %d, got %v", seconds, err)
	}
}
func TestContentRateIPCookieAndWindow(t *testing.T) {
	at := domain.Time(1700000000e9)
	settings := defaultContentRateSettings()
	var l contentRateLimiter
	for i := 1; i <= 20; i++ {
		if err := l.reserve(contentTestEntry(at, 1, byte(i)), settings); err != nil {
			t.Fatal(i, err)
		}
	}
	requireContentLimited(t, l.reserve(contentTestEntry(at, 1, 21), settings), 60)
	// IPを替えても、同じCookie・内容は許可しない。
	requireContentLimited(t, l.reserve(contentTestEntry(at+1e9, 2, 1), settings), 59)
	requireContentLimited(t, l.reserve(contentTestEntry(at+30e9, 2, 1), settings), 30)
	different := contentTestEntry(at+1e9, 1, 1)
	different.content = domain.Hash{10}
	if err := l.reserve(different, settings); err != nil {
		t.Fatal("different content", err)
	}
	if err := l.reserve(contentTestEntry(at+60e9, 1, 1), settings); err != nil {
		t.Fatal("exact expiry", err)
	}
}
func TestContentRatePendingCancelAndSettings(t *testing.T) {
	at := domain.Time(1700000000e9)
	settings := defaultContentRateSettings()
	var l contentRateLimiter
	entry := contentTestEntry(at, 1, 1)
	if err := l.reserve(entry, settings); err != nil {
		t.Fatal(err)
	}
	requireContentLimited(t, l.reserve(contentTestEntry(at, 2, 1), settings), 60)
	l.remove(entry.id)
	if len(l.expiry) != 0 {
		t.Fatal("cancelled reservation retained")
	}
	if err := l.reserve(contentTestEntry(at, 2, 1), settings); err != nil {
		t.Fatal("failed reservation consumed", err)
	}
	settings.CookiePosts = 2
	if err := l.reserve(contentTestEntry(at+1e9, 3, 1), settings); err != nil {
		t.Fatal("increased count", err)
	}
	settings.CookieSeconds = 600
	requireContentLimited(t, l.reserve(contentTestEntry(at+60e9, 4, 1), settings), 540)
	settings.CookiePosts = 1
	requireContentLimited(t, l.reserve(contentTestEntry(at+60e9, 4, 1), settings), 541)
	l.expire(at + 601e9)
	if len(l.entries) != 0 || len(l.subjects) != 0 || len(l.expiry) != 0 {
		t.Fatal("expired history retained")
	}
}

// TestContentRateHTTPAndRecovery は通常専ブラの同一本文を明示的に429とし、DAT不増加と復旧後の拒否を確認する。
func TestContentRateHTTPAndRecovery(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() { repo.Close() }()
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer func() { server.Close() }()
	create := url.Values{"bbs": {"news"}, "subject": {"同一内容試験"}, "MESSAGE": {"最初の投稿"}, "oimo_request_id": {"content-create-0001"}}
	for i := 0; i < 2; i++ {
		res, page := request("POST", "/test/bbs.cgi", create)
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, page)
		}
	}
	// 初回の結果リンクからスレッドキーを取得する。
	_, page := request("POST", "/test/bbs.cgi", create)
	decoded, err := textcodec.Decode([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	marker := "/test/read.cgi/news/"
	pos := strings.Index(decoded, marker)
	if pos < 0 {
		t.Fatal("missing result link", decoded)
	}
	key := strings.Split(decoded[pos+len(marker):], "/")[0]
	fields := url.Values{"bbs": {"news"}, "key": {key}, "MESSAGE": {"同じ本文"}}
	res, page := request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 {
		t.Fatal("first reply", res.StatusCode, page)
	}
	assertBlocked := func() {
		t.Helper()
		res, page := request("POST", "/test/bbs.cgi", fields)
		if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
			t.Fatal("same content", res.StatusCode, page)
		}
		_, dat := request("GET", "/news/dat/"+key+".dat", nil)
		if strings.Count(dat, "\n") != 2 {
			t.Fatal("rejected reply appended", dat)
		}
	}
	assertBlocked()
	// 同じ接続元でも別CookieならIP枠内で新規投稿できる。
	saved := cookies["oimo_anon"]
	delete(cookies, "oimo_anon")
	_, _ = request("POST", "/test/bbs.cgi", fields)
	res, page = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 {
		t.Fatal("another Cookie within IP quota", res.StatusCode, page)
	}
	cookies["oimo_anon"] = saved
	// 復旧後もCookieの60秒枠を維持する。
	server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	var fresh map[string]*http.Cookie
	server, request, fresh = anonymousHTTP(t, repo, site)
	for k, v := range cookies {
		fresh[k] = v
	}
	res, page = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 429 {
		t.Fatal("restart reset", res.StatusCode, page)
	}
	// 要求IDの再送は追加投稿に数えず、受理済みの元結果を返す。
	res, page = request("POST", "/test/bbs.cgi", create)
	if res.StatusCode != 200 {
		t.Fatal("explicit retry blocked", res.StatusCode, page)
	}
	keyNumber, _ := strconv.ParseUint(key, 10, 64)
	thread, err := repo.Thread(t.Context(), owner, keyNumber)
	if err != nil || thread.PostCount != 3 {
		t.Fatal("wrong durable count", err, thread)
	}
}

func TestContentRateOperationsHTTPPersistence(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	client.login(adminTestSecret)
	res, body := client.request("GET", "/api/v1/operations", "", nil)
	var view struct {
		Data operationsTestAPI `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	settings := OperationSettings(view.Data.Settings)
	if settings.contentRates() != defaultContentRateSettings() {
		t.Fatal(settings)
	}
	custom := ContentRateSettings{90, 25, 120, 2}
	settings.ContentRates = &custom
	raw, _ := json.Marshal(settings.editable())
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"content-rate-save-0001"}}
	res, body = client.request("POST", "/api/v1/operations", string(raw), headers)
	if res.StatusCode != 200 || repo.operations().contentRates() != custom {
		t.Fatal(res.StatusCode, body)
	}
	// 旧APIによる省略では保存済みの条件を維持する。
	headers.Set("If-Match", res.Header.Get("ETag"))
	headers.Set("Idempotency-Key", "content-rate-legacy-0001")
	var old map[string]json.RawMessage
	_ = json.Unmarshal(raw, &old)
	delete(old, "same_content")
	raw, _ = json.Marshal(old)
	res, body = client.request("POST", "/api/v1/operations", string(raw), headers)
	if res.StatusCode != 200 || repo.operations().contentRates() != custom {
		t.Fatal("old API reset", res.StatusCode, body)
	}
	// HTML画面の四つの入力値からも保存する。
	_, page := client.request("GET", "/operations", "", nil)
	fields := pageFields(page)
	for name, value := range map[string]string{"maintenance_enabled": "false", "interval_seconds": "300", "max_threads": "5", "max_seconds": "30", "egress_mbps": "80", "window_minutes": "1440", "quorum": "3", "stop_minutes": "10", "report_interval_minutes": "10", "content_ip_seconds": "60", "content_ip_posts": "21", "content_cookie_seconds": "60", "content_cookie_posts": "3"} {
		fields.Set(name, value)
	}
	res, body = client.request("POST", "/operations", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("HTML save", res.StatusCode, body)
	}
	custom = ContentRateSettings{60, 21, 60, 3}
	client.server.Close()
	repo.Close()
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if repo.operations().contentRates() != custom {
		t.Fatal("settings not restored")
	}
	var site siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader < contentRateReader {
		t.Fatal("reader", site.MinimumReader, err)
	}
	for _, invalid := range []ContentRateSettings{{0, 20, 60, 1}, {601, 20, 60, 1}, {60, 0, 60, 1}, {60, 1001, 60, 1}, {60, 20, 0, 1}, {60, 20, 601, 1}, {60, 20, 60, 0}, {60, 20, 60, 1001}} {
		if invalid.valid() {
			t.Fatal(fmt.Sprint(invalid))
		}
	}
}

// TestContentRateConcurrentHTTP は同じCookieの並列新規要求を一件だけ保存し、再送成功に見せない。
func TestContentRateConcurrentHTTP(t *testing.T) {
	_, repo, site, owner := anonymousFixture(t, "required")
	defer repo.Close()
	if err := repo.admission.applyBoardRates(owner, AdminRateSettings{false, 1, 100, 600, 1, 6}, time.Now()); err != nil {
		t.Fatal(err)
	}
	server := formServer(t, repo, site, owner)
	defer server.Close()
	first, err := sendForm(server, url.Values{"bbs": {"news"}, "subject": {"並列"}, "MESSAGE": {"最初"}})
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	type result struct {
		value formResult
		err   error
	}
	results := make(chan result, 32)
	for range 32 {
		go func() {
			v, e := sendForm(server, url.Values{"bbs": {"news"}, "key": {strconv.FormatUint(first.Key, 10)}, "MESSAGE": {"同じ内容の並列送信"}})
			results <- result{v, e}
		}()
	}
	accepted := 0
	for range 32 {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		if r.value.Duplicate {
			t.Fatal("new request treated as replay")
		}
		if r.value.Accepted {
			accepted++
		}
	}
	if accepted != 1 {
		t.Fatal("concurrent accepted", accepted)
	}
	snapshot, err := repo.Thread(t.Context(), owner, first.Key)
	if err != nil || snapshot.PostCount != 2 {
		t.Fatal(snapshot, err)
	}
}

// TestContentRateIPQuotaHTTP は既存の有効なCookie群から同じIPで20件を受け付け、21件目を429にする。
func TestContentRateIPQuotaHTTP(t *testing.T) {
	_, repo, site, owner := anonymousFixture(t, "required")
	defer repo.Close()
	if err := repo.admission.applyBoardRates(owner, AdminRateSettings{false, 1, 100, 600, 1, 6}, time.Now()); err != nil {
		t.Fatal(err)
	}
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer server.Close()
	create := url.Values{"bbs": {"news"}, "subject": {"IP枠"}, "MESSAGE": {"最初"}, "oimo_request_id": {"content-ip-create-0001"}}
	for range 2 {
		_, _ = request("POST", "/test/bbs.cgi", create)
	}
	_, page := request("POST", "/test/bbs.cgi", create)
	decoded, err := textcodec.Decode([]byte(page))
	if err != nil {
		t.Fatal(err)
	}
	marker := "/test/read.cgi/news/"
	pos := strings.Index(decoded, marker)
	if pos < 0 {
		t.Fatal(decoded)
	}
	key := strings.Split(decoded[pos+len(marker):], "/")[0]
	fields := url.Values{"bbs": {"news"}, "key": {key}, "MESSAGE": {"同じ本文を複数Cookieから送信"}}
	for i := 1; i <= 21; i++ {
		// 発行制限の試験と分け、既に発行済みのCookieを持つ利用者群を再現する。
		now := time.Now().Unix()
		raw, err := abuse.IssueAnon(abuse.Anon{ID: domain.NewID(), Generation: uint64(repo.anonymous.policy.Generation), Issued: now, Expires: now + 30*86400}, repo.anonymous.key[:], 4)
		if err != nil {
			t.Fatal(err)
		}
		cookies["oimo_anon"] = &http.Cookie{Name: "oimo_anon", Value: raw}
		res, page := request("POST", "/test/bbs.cgi", fields)
		want := 200
		if i == 21 {
			want = 429
		}
		if res.StatusCode != want {
			t.Fatal(i, res.StatusCode, page)
		}
		if i == 21 && res.Header.Get("Retry-After") == "" {
			t.Fatal("no wait header")
		}
	}
	_, dat := request("GET", "/news/dat/"+key+".dat", nil)
	if strings.Count(dat, "\n") != 21 {
		t.Fatal("IP quota durable count", strings.Count(dat, "\n"))
	}
}
