// 通常返信による短い通報・公開範囲・10分停止を確認する。
package bootstrap

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
)

func TestReportCommand(t *testing.T) {
	for _, tc := range []struct {
		body   string
		number uint32
		ok     bool
	}{
		{"!report 15 広告の連投", 15, true},
		{"!report >>15 広告", 15, true},
		{"  !report\t15  広告\n補足  ", 15, true},
		{"!report 15", 15, true},
		{"!report 15   ", 15, true},
		{">>15\n!report 広告の連投", 15, true},
		{">>15\n!report", 15, true},
		{">>15 !report 広告の連投", 15, true},
		{">>15 !report", 15, true},
		{">>15\t!report", 15, true},
		{"  >>15\r\n!report  ", 15, true},
		{">>15\n!report\n補足", 15, true},
		{">>15\n普通の返信", 0, false},
		{">>15\n!reporting", 0, false},
		{">>15 >>16\n!report 理由", 0, false},
		{">>15-16\n!report", 0, false},
		{">>015\n!report", 0, false},
		{">>0\n!report", 0, false},
		{">>4294967296\n!report", 0, false},
		{"!report", 0, false},
		{"!report 0 理由", 0, false},
		{"!report 015 理由", 0, false},
		{"!report 15-20 理由", 0, false},
		{"!report 4294967296 理由", 0, false},
		{"説明 !report 15 理由", 0, false},
		{"!reporting 15 理由", 0, false},
	} {
		n, ok := parseAutoReportCommand(tc.body)
		if n != tc.number || ok != tc.ok {
			t.Fatalf("command %q: %d %t", tc.body, n, ok)
		}
	}
}

func TestReportShortcutHTTP(t *testing.T) {
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
		observer, err := evidence.NewHTTPObserver(site, domain.NewID(), "report-shortcut-test")
		if err != nil {
			t.Fatal(err)
		}
		server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
		server.Config.ConnContext = observer.ConnContext
		server.Start()
		return server
	}
	server := start()
	defer func() { server.Close() }()
	victim := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.101.0.1")
	if body := victim.post(t, "news", "", "TARGET", "shortcut-target-create"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("target creation")
	}
	key := strings.Split(victim.request(t, "/news/subject.txt", nil), ".dat<>")[0]
	reader := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.102.0.1")
	if body := reader.post(t, "news", key, ">>1-2\n!report", "shortcut-invalid-target"); !strings.Contains(body, "!report") || strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("invalid target accepted")
	}
	if len(repo.autoReportVotes) != 0 {
		t.Fatal("invalid report changed votes")
	}
	if body := reader.post(t, "news", key, ">>1\n!report 広告の連投", "shortcut-first-report"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("first command")
	}
	if body := reader.post(t, "news", key, ">>1\n!report 広告の連投", "shortcut-first-report"); !strings.Contains(body, "同一内容を受理済み") {
		t.Fatal("command retry")
	}
	second := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.103.0.1")
	if body := second.post(t, "news", key, ">>1\n!report", "shortcut-second-report"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("second command")
	}
	if len(repo.posting[owner].denials) != 0 {
		t.Fatal("two commands stopped target")
	}
	// 通報板へ転載せず、元スレッドの原本から2票を復元する。
	server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = start()
	victim.server = server.URL
	third := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.104.0.1")
	if body := third.post(t, "news", key, ">>1 !report   ", "shortcut-third-report"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("third command")
	}
	if len(repo.posting[owner].denials) != 1 {
		t.Fatal("same-thread quorum lost")
	}
	for _, entry := range repo.posting[owner].denials {
		if entry.rule.Expires-entry.rule.Starts != domain.Time(10*time.Minute) {
			t.Fatal("stop must be ten minutes")
		}
	}
	if body := victim.post(t, "news", key, "STOPPED", "shortcut-target-blocked"); !strings.Contains(body, "規制されています") {
		t.Fatal("target not stopped")
	}
	dat := third.request(t, "/news/dat/"+key+".dat", nil)
	if strings.Count(dat, "\n") != 4 || !strings.Contains(dat, "&gt;&gt;1<br>!report") {
		t.Fatal("ordinary reply publication or invalid/retry count")
	}
	if subject := third.request(t, "/report/subject.txt", nil); !strings.HasPrefix(subject, "1.dat<>") {
		t.Fatal("unexpected report-board copy")
	}
}
