// 自動受付を各板の末尾へ一つ表示し、私有通報・再送・復旧で公開DATを増やさない。
package bootstrap

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestPrivateReportReceiptHTTP(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if _, err := repo.CreateBoard(t.Context(), "report", "通報"); err != nil {
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
		obs, err := evidence.NewHTTPObserver(site, domain.NewID(), "private-report-test")
		if err != nil {
			t.Fatal(err)
		}
		s := httptest.NewUnstartedServer(repo.SiteWebHandler(obs))
		s.Config.ConnContext = obs.ConnContext
		s.Start()
		return s
	}
	server := start()
	defer func() { server.Close() }()
	victim := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.111.0.1")
	if body := victim.post(t, "news", "", "Target", "private-receipt-target"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("target creation", body)
	}
	subject := victim.request(t, "/news/subject.txt", nil)
	lines := strings.Split(strings.TrimSpace(subject), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[1], "1.dat<>通報受付スレッド (1)") {
		t.Fatal("receipt not unique and last")
	}
	key := strings.Split(lines[0], ".dat<>")[0]
	before := victim.request(t, "/news/dat/1.dat", nil)
	if strings.Count(before, "\n") != 1 || !strings.Contains(before, "通報は公開されず") {
		t.Fatal("receipt instructions")
	}
	page := victim.request(t, "/test/read.cgi/news/1/", nil)
	if !strings.Contains(page, "返信する") {
		t.Fatal("receipt not replyable")
	}
	// 返信受付に通常の新規スレッド用タイトル上限を持ち込まない。
	_, err = repo.posting[owner].worker.Submit(t.Context(), func() (any, error) {
		b := repo.posting[owner]
		var settings boardValue
		if err := strictjson.Decode(b.control.State().Rows["board:state"].Value, &settings); err != nil {
			return nil, err
		}
		settings.Settings.Input.TitleBytes = 1
		settings.Settings.Version++
		return nil, appendControl(b.control, "board_settings", []store.Mutation{mutation("board", "state", settings, nil)}, []string{owner.String()})
	})
	if err != nil {
		t.Fatal(err)
	}
	message := "対象URL：" + cfg.Public.BaseURL + "/test/read.cgi/news/" + key + "/1/"
	first := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.112.0.1")
	post := func(c *autoReportHTTPClient, body, id string) {
		t.Helper()
		if response := c.post(t, "news", "1", body, id); !strings.Contains(response, "投稿を受け付けました") {
			t.Fatal("private report rejected", response)
		}
	}
	post(first, message+"\n理由：PRIVATE-REASON-DO-NOT-PUBLISH", "private-receipt-first")
	if response := first.post(t, "news", "1", message+"\n理由：PRIVATE-REASON-DO-NOT-PUBLISH", "private-receipt-first"); !strings.Contains(response, "同一内容を受理済み") {
		t.Fatal("HTTP retry")
	}
	privateKey, err := reportKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	firstIDs, err := reportFiles(cfg.DataDir)
	if err != nil || len(firstIDs) != 1 {
		t.Fatal("first private record", err)
	}
	stored, err := readReport(cfg.DataDir, firstIDs[0], privateKey)
	clear(privateKey[:])
	if err != nil {
		t.Fatal(err)
	}
	// HTTPの試行上限は維持し、1000回を超える再送照合は所有列内で確認する。
	for i := 0; i < 1001; i++ {
		_, err := repo.posting[owner].worker.Submit(t.Context(), func() (any, error) {
			result, ok, err := repo.privateReportRetry(repo.posting[owner], stored.Automatic.Dedup, domain.Time(time.Now().UnixNano()))
			if err == nil && (!ok || !result.Duplicate) {
				return nil, fmt.Errorf("retry not retained")
			}
			return nil, err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if response := first.post(t, "news", "1", "対象URL："+cfg.Public.BaseURL+"/test/read.cgi/news/"+key+"/1-2/", "private-receipt-invalid"); strings.Contains(response, "投稿を受け付けました") {
		t.Fatal("invalid range accepted")
	}
	second := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.113.0.1")
	post(second, message, "private-receipt-second")
	if len(repo.posting[owner].denials) != 0 {
		t.Fatal("two reports stopped target")
	}
	for _, board := range []string{"news", "report"} {
		s := first.request(t, "/"+board+"/subject.txt", nil)
		// 通常キーの末尾が1でも受付として数えず、行頭の固定キーだけを照合する。
		receipts := 0
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, "1.dat<>") {
				receipts++
			}
		}
		if receipts != 1 {
			t.Fatalf("receipt count: board=%s count=%d", board, receipts)
		}
	}
	server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = start()
	victim.server = server.URL
	third := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.114.0.1")
	post(third, message, "private-receipt-third")
	if len(repo.posting[owner].denials) != 1 {
		t.Fatal("private votes not restored")
	}
	if response := victim.post(t, "news", key, "Blocked", "private-receipt-blocked"); !strings.Contains(response, "規制されています") {
		t.Fatal("target not stopped")
	}
	if after := third.request(t, "/news/dat/1.dat", nil); after != before || strings.Contains(after, "PRIVATE-REASON") {
		t.Fatal("private report entered public DAT")
	}
	if after := third.request(t, "/news/subject.txt", nil); after != subject {
		t.Fatal("private reports bumped count or ordering")
	}
	secret, err := reportKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret[:])
	ids, err := reportFiles(cfg.DataDir)
	if err != nil || len(ids) != 3 {
		t.Fatal("private records or retry count", err, len(ids))
	}
	for _, id := range ids {
		v, err := readReport(cfg.DataDir, id, secret)
		if err != nil || v.Automatic == nil || v.Thread != domain.U64(mustReceiptKey(t, key)) {
			t.Fatal("private durable record", err)
		}
	}
	if _, err := repo.CreateBoard(t.Context(), "newboard", "新しい板"); err != nil {
		t.Fatal(err)
	}
	if s := third.request(t, "/newboard/subject.txt", nil); !strings.HasPrefix(s, "1.dat<>") {
		t.Fatal("new board receipt")
	}
	for _, entry := range repo.posting[owner].denials {
		if entry.rule.Expires-entry.rule.Starts != domain.Time(10*time.Minute) {
			t.Fatal("stop duration")
		}
	}
}

func mustReceiptKey(t *testing.T, key string) uint64 {
	t.Helper()
	var n uint64
	if _, err := fmt.Sscan(key, &n); err != nil {
		t.Fatal(err)
	}
	return n
}
