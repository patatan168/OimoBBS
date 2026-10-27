// 公開通報のURL境界・異なるID/IPの成立条件・実TCP投稿・再起動・期限解除を検査する。
package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/textcodec"
)

func TestAutoReportReference(t *testing.T) {
	origin := "https://bbs.example"
	for _, tc := range []struct {
		target, reason string
		valid          bool
	}{
		{origin + "/test/read.cgi/news/123/4", "荒らし", true},
		{origin + "/test/read.cgi/news/123/4/", "荒らし", true},
		{origin + "/test/read.cgi/news/123/4", "", false},
		{"https://other.example/test/read.cgi/news/123/4", "荒らし", false},
		{origin + "/test/read.cgi/news/123/4?x", "荒らし", false},
		{origin + "/test/read.cgi/news/123/4-6", "荒らし", false},
		{origin + "/test/read.cgi/news/0123/4", "荒らし", false},
		{origin + "/test/read.cgi/news/123/0", "荒らし", false},
		{origin + "/test/read.cgi/news/123/l50", "荒らし", false},
		{origin + "/test/read.cgi/news/123/4#x", "荒らし", false},
	} {
		_, ok := parseAutoReport("対象URL："+tc.target+"\n理由："+tc.reason, origin)
		if ok != tc.valid {
			t.Fatalf("reference acceptance: %q", tc.target)
		}
	}
	if _, ok := parseAutoReport("通報: "+origin+"/test/read.cgi/news/123/4\r\n理由: 荒らし", origin); !ok {
		t.Fatal("ASCII syntax")
	}
	if _, ok := parseAutoReport("対象URL："+origin+"/test/read.cgi/news/123/4\n対象URL："+origin+"/test/read.cgi/news/123/5\n理由：荒らし", origin); ok {
		t.Fatal("ambiguous targets")
	}
}

func TestAutoReportConfiguration(t *testing.T) {
	cfg := testConfig(t)
	for _, policy := range []*AutoReportConfig{
		{"", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)},
		{"report", ""},
		{"report", time.Now().Add(time.Hour).UTC().Format(time.RFC3339)},
	} {
		cfg.AutoReports = policy
		if cfg.validate() == nil {
			t.Fatal("invalid automatic reporting configuration")
		}
	}
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	if err := cfg.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAutoReportQuorum(t *testing.T) {
	at := domain.Time(time.Hour)
	vote := func(id, ip byte, elapsed time.Duration) autoReportVote {
		return autoReportVote{domain.ID{id}, domain.Hash{id}, domain.Hash{ip}, at + domain.Time(elapsed), autoReportReference{}}
	}
	var votes []autoReportVote
	var ready bool
	votes, ready = collectAutoReport(votes, vote(1, 1, 0))
	if ready || len(votes) != 1 {
		t.Fatal("one report")
	}
	votes, ready = collectAutoReport(votes, vote(1, 2, time.Second))
	if ready || len(votes) != 1 {
		t.Fatal("same ID, different IP")
	}
	votes, ready = collectAutoReport(votes, vote(2, 1, time.Second))
	if ready || len(votes) != 1 {
		t.Fatal("same IP, different ID")
	}
	votes, ready = collectAutoReport(votes, vote(3, 3, time.Second))
	if ready || len(votes) != 2 {
		t.Fatal("two reports")
	}
	votes, ready = collectAutoReport(votes, vote(4, 4, 2*time.Second))
	if !ready || len(votes) != 3 {
		t.Fatal("three independent reports")
	}
	votes, ready = collectAutoReport(votes, vote(5, 5, autoReportWindow+2*time.Second))
	if ready || len(votes) != 1 {
		t.Fatal("exact window expiration")
	}
	votes = []autoReportVote{vote(1, 1, 2*time.Second), vote(2, 2, time.Second)}
	_, ready = collectAutoReport(votes, vote(3, 3, 0))
	if !ready {
		t.Fatal("HTTP completion order must not lose votes")
	}
}

type autoReportHTTPClient struct {
	client         *http.Client
	server, origin string
}

// newAutoReportHTTPClient は実TCP送信元とCookie jarを利用者ごとに分離する。転送ヘッダーは使わない。
func newAutoReportHTTPClient(t *testing.T, server, origin, ip string) *autoReportHTTPClient {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}
	transport := &http.Transport{DialContext: dialer.DialContext}
	t.Cleanup(transport.CloseIdleConnections)
	return &autoReportHTTPClient{&http.Client{Transport: transport, Jar: jar, Timeout: 30 * time.Second}, server, origin}
}

func (c *autoReportHTTPClient) request(t *testing.T, path string, fields url.Values) string {
	t.Helper()
	method := "GET"
	if fields != nil {
		method = "POST"
	}
	req, _ := http.NewRequest(method, c.server+path, strings.NewReader(fields.Encode()))
	origin, _ := url.Parse(c.origin)
	req.Host = origin.Host
	if fields != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		req.Header.Set("Origin", c.origin)
	}
	res, err := c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(res.Header.Get("Content-Type")), "utf-8") {
		return string(raw)
	}
	body, _ := textcodec.Decode(raw)
	return body
}

func (c *autoReportHTTPClient) post(t *testing.T, board, key, body, id string) string {
	t.Helper()
	fields := url.Values{"bbs": {board}, "MESSAGE": {body}, "oimo_request_id": {id}}
	if key == "" {
		fields.Set("subject", "通報機能の試験")
	} else {
		fields.Set("key", key)
	}
	var result string
	for range 4 {
		result = c.request(t, "/test/bbs.cgi", fields)
		if !strings.Contains(result, "2ch_X:cookie") {
			break
		}
	}
	return result
}

func TestAutoReportHTTPRecoveryAndTemporaryStop(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if _, err := repo.CreateBoard(t.Context(), "report", "通報"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateBoard(t.Context(), "other", "別の板"); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-time.Second).UTC().Format(time.RFC3339)}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	start := func() *httptest.Server {
		observer, e := evidence.NewHTTPObserver(site, domain.NewID(), "auto-report-test")
		if e != nil {
			t.Fatal(e)
		}
		server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
		server.Config.ConnContext = observer.ConnContext
		server.Start()
		return server
	}
	server := start()
	defer func() { server.Close() }()
	victim := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.81.0.1")
	if body := victim.post(t, "news", "", "TARGET", "auto-report-target-create"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("target post")
	}
	key := strings.Split(victim.request(t, "/news/subject.txt", nil), ".dat<>")[0]
	seed := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.82.0.1")
	if body := seed.post(t, "report", "", "通報受付", "auto-report-thread-create"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("report thread")
	}
	reportKey := strings.Split(seed.request(t, "/report/subject.txt", nil), ".dat<>")[0]
	message := "対象URL：" + cfg.Public.BaseURL + "/test/read.cgi/news/" + key + "/1\n理由：荒らし"
	if body := victim.post(t, "report", reportKey, message, "auto-report-self-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("self report reception")
	}
	if len(repo.autoReportVotes) != 0 {
		t.Fatal("self report counted")
	}
	first := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.83.0.1")
	if body := first.post(t, "report", reportKey, message, "auto-report-first-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("first vote")
	}
	if body := first.post(t, "report", reportKey, message, "auto-report-first-vote"); !strings.Contains(body, "同一内容を受理済み") {
		t.Fatal("retry receipt")
	}
	if len(repo.posting[owner].denials) != 0 {
		t.Fatal("one reporter must not stop target")
	}
	second := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.84.0.1")
	if body := second.post(t, "report", reportKey, message, "auto-report-second-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("second vote")
	}
	if len(repo.posting[owner].denials) != 0 {
		t.Fatal("two reports must not stop target")
	}
	// 2票の状態で実repositoryを閉じ、署名済み受理記録から再構築する。
	server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = start()
	victim.server = server.URL
	third := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.85.0.1")
	// 受理原本だけ保存され、判定へ進めなかった状態を作る。
	repo.autoReportBoard = domain.ID{}
	if body := third.post(t, "report", reportKey, message, "auto-report-third-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("third vote")
	}
	if len(repo.posting[owner].denials) != 0 {
		t.Fatal("unprocessed report unexpectedly applied")
	}
	server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = start()
	victim.server = server.URL
	if len(repo.posting[owner].denials) != 1 {
		t.Fatal("three reports did not produce one rule")
	}
	var rule denialRule
	for _, entry := range repo.posting[owner].denials {
		rule = entry.rule
	}
	if rule.Expires-rule.Starts != domain.Time(10*time.Minute) {
		t.Fatal("temporary duration")
	}
	if body := victim.post(t, "news", key, "SHOULD-BE-STOPPED", "auto-report-target-blocked"); !strings.Contains(body, "規制されています") {
		t.Fatal("reported target not stopped")
	}
	shared := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.81.0.1")
	if body := shared.post(t, "news", key, "SAME-IP-OTHER-USER", "auto-report-shared-ip"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("shared IP collateral")
	}
	if body := victim.post(t, "other", "", "OTHER-BOARD", "auto-report-other-board"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("other board collateral")
	}
	fourth := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.86.0.1")
	if body := fourth.post(t, "report", reportKey, message, "auto-report-fourth-vote"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("fourth vote")
	}
	if len(repo.posting[owner].denials) != 1 {
		t.Fatal("active ban renewed")
	}
	// 規制保存後の再起動でも同じ期限を維持する。
	server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = start()
	victim.server = server.URL
	if got := repo.posting[owner].denials[rule.ID].rule; got.Expires != rule.Expires || len(repo.posting[owner].denials) != 1 {
		t.Fatal("restart extended stop")
	}
	if body := victim.post(t, "news", key, "RESTART-STILL-STOPPED", "auto-report-restart-blocked"); !strings.Contains(body, "規制されています") {
		t.Fatal("restart lost stop")
	}
	// 実時間10分は待たず、投稿workerの既存時計を期限境界へ進める。
	_, err = repo.posting[owner].worker.Submit(context.Background(), func() (any, error) {
		repo.posting[owner].clock = func() time.Time { return time.Unix(0, int64(rule.Expires)) }
		denied, _, err := repo.posting[owner].matchingRules(netip.MustParseAddr("127.81.0.1"), postinput.Input{}, domain.Hash{}, false, rule.Expires)
		if denied {
			return nil, fmt.Errorf("rule remained active at expiry")
		}
		return nil, err
	})
	if err != nil {
		t.Fatal(err)
	}
	if body := victim.post(t, "news", key, "AFTER-TEMPORARY-STOP", "auto-report-expiry-accepted"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("target not released at expiry")
	}
}
