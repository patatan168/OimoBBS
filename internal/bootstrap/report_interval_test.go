// レス指定の導線、送信間隔の永続判定、共有回線と照会の分離を検証する。
package bootstrap

import (
	"errors"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestReportResponseLinkAndPrefill(t *testing.T) {
	_, repo, c, _, key := reportTestSetup(t)
	defer repo.Close()
	defer c.server.Close()
	status, body := c.request("GET", "/test/read.cgi/reports/"+key+"/", nil)
	if status != 200 || !strings.Contains(body, "/reports?board=reports&amp;thread="+key+"&amp;ranges=1#report-form") {
		t.Fatal("response link", status, body)
	}
	status, body = c.request("GET", "/reports?board=reports&thread="+key+"&ranges=1", nil)
	if status != 200 {
		t.Fatal(status, body)
	}
	for name, want := range map[string]string{"board": "reports", "thread": key, "ranges": "1"} {
		if got := reportInputValue(body, name); got != want {
			t.Fatalf("%s: %q", name, got)
		}
	}
	for _, query := range []string{"board=reports&thread=" + key + "&ranges=1&secret=private", "board=reports&board=other&thread=" + key + "&ranges=1", "board=reports&thread=01&ranges=1", "board=reports&thread=" + key + "&ranges=0"} {
		if status, _ := c.request("GET", "/reports?"+query, nil); status != 404 {
			t.Fatal(query, status)
		}
	}
}

func TestReportSubmissionCooldownHTTPAndRestart(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	defer func() { c.server.Close(); repo.Close() }()
	cookie := c.cookie
	id, secret := createTestReport(t, c, key)
	fields := url.Values{"csrf": {c.token}, "board": {"reports"}, "thread": {key}, "ranges": {"1"}, "category": {"important"}, "reason": {"入力を保持<script>bad</script>"}, "contact": {"mail@example.test"}}
	assertLimited := func() {
		t.Helper()
		status, body := c.request("POST", "/reports", fields)
		if status != 429 || !strings.Contains(body, "あと約10分") || strings.Contains(body, "<script>bad</script>") || !strings.Contains(body, "入力を保持&lt;script&gt;") || reportInputValue(body, "contact") != "mail@example.test" {
			t.Fatal(status, body)
		}
	}
	assertLimited()
	if status, _ := c.request("POST", "/reports/lookup", url.Values{"csrf": {c.token}, "id": {id.String()}, "secret": {secret}}); status != 200 {
		t.Fatal("lookup shares cooldown", status)
	}
	c.server.Close()
	repo.Close()
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c = newReportTestClient(t, repo)
	c.cookie = cookie
	_, body := c.request("GET", "/reports", nil)
	c.token = pageFields(body).Get("csrf")
	fields.Set("csrf", c.token)
	assertLimited()
	ids, err := reportFiles(cfg.DataDir)
	if err != nil || len(ids) != 1 {
		t.Fatal("rejected request saved", ids, err)
	}
}

func TestReportSubmissionWindowAndSharedNetwork(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	defer repo.Close()
	defer c.server.Close()
	id, _ := createTestReport(t, c, key)
	signing, err := reportKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := readReport(cfg.DataDir, id, signing)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(0, int64(saved.Created))
	ids := []domain.ID{id}
	candidate := saved
	limited := func(at time.Time, seconds uint64) {
		t.Helper()
		err := repo.reportSubmissionRate(ids, candidate, signing, at)
		var rate *abuse.RateLimited
		if !errors.As(err, &rate) || rate.RetryAfter != seconds {
			t.Fatal("retry", err, seconds)
		}
	}
	limited(now.Add(9*time.Minute), 60)
	if err := repo.reportSubmissionRate(ids, candidate, signing, now.Add(10*time.Minute)); err != nil {
		t.Fatal("boundary", err)
	}
	actor := reportActorHash(signing, "another-browser")
	candidate.ReporterHash = &actor
	if err := repo.reportSubmissionRate(ids, candidate, signing, now); err != nil {
		t.Fatal("shared network", err)
	}
	for i := 0; i < 2; i++ {
		copy := saved
		copy.ID = domain.NewID()
		actor := reportActorHash(signing, strconv.Itoa(i))
		copy.ReporterHash = &actor
		if err := writeReport(cfg.DataDir, copy, signing); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, copy.ID)
	}
	limited(now, 600)
	candidate.SourceIP = "192.0.2.100"
	if err := repo.reportSubmissionRate(ids, candidate, signing, now); err != nil {
		t.Fatal("unrelated network", err)
	}
	settings := repo.operations()
	settings.ReportIntervalMinutes = 5
	repo.liveOperations.Store(&operationState{Settings: settings})
	candidate = saved
	if err := repo.reportSubmissionRate(ids, candidate, signing, now.Add(5*time.Minute)); err != nil {
		t.Fatal("live interval", err)
	}
}

func TestReportIntervalLegacyJSON(t *testing.T) {
	raw := `{"maintenance":{"enabled":false,"max_seconds":30,"interval_seconds":300,"max_threads":5},"egress_budget_bits_per_second":80000000,"cache_bytes":0,"cache_workers":0,"reports":{"window_seconds":86400,"quorum":3,"stop_seconds":600}}`
	var settings OperationSettings
	if err := strictjson.Decode([]byte(raw), &settings); err != nil || settings.reportIntervalMinutes() != 10 {
		t.Fatal(err, settings)
	}
	for _, broken := range []string{strings.Replace(raw, `"cache_bytes":0,`, "", 1), strings.Replace(raw, `"cache_bytes":0`, `"cache_bytes":0,"cache_bytes":0`, 1), strings.Replace(raw, `"cache_bytes":0`, `"unknown":0`, 1)} {
		if strictjson.Decode([]byte(broken), &settings) == nil {
			t.Fatal("accepted malformed legacy", broken)
		}
	}
}

func reportInputValue(body, name string) string {
	match := regexp.MustCompile(`<input[^>]* name="` + regexp.QuoteMeta(name) + `"[^>]* value="([^"]*)"`).FindStringSubmatch(body)
	if len(match) != 2 {
		return ""
	}
	return html.UnescapeString(match[1])
}

func TestReportIntervalLegacySignedReport(t *testing.T) {
	cfg, repo, c, _, key := reportTestSetup(t)
	defer repo.Close()
	defer c.server.Close()
	id, _ := createTestReport(t, c, key)
	signing, err := reportKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	v, err := readReport(cfg.DataDir, id, signing)
	if err != nil {
		t.Fatal(err)
	}
	v.ReporterHash = nil
	if err := writeReport(cfg.DataDir, v, signing); err != nil {
		t.Fatal(err)
	}
	legacy, err := readReport(cfg.DataDir, id, signing)
	if err != nil || legacy.ReporterHash != nil {
		t.Fatal("legacy signature", err)
	}
}
