// 保存ログ・全板規制の実HTTP、再送、再起動、ダミー分離と入力境界を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/securitylog"
	"oimobbs/internal/store"
	"strings"
	"testing"
	"time"
)

func postGlobalEdit(t *testing.T, c *adminClient, edit globalRuleEdit) AdminGlobalRules {
	t.Helper()
	if status := c.reauth(adminTestSecret); status != 200 {
		t.Fatal("reauth", status)
	}
	res, body := c.request("GET", "/api/v1/global-rules", "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}}
	raw, _ := json.Marshal(edit)
	res, body = c.request("POST", "/api/v1/global-rules", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	retry, retryBody := c.request("POST", "/api/v1/global-rules", string(raw), headers)
	if retry.StatusCode != 200 {
		t.Fatal("retry", retry.StatusCode, retryBody)
	}
	var v struct {
		Data AdminGlobalRules `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v.Data
}

func TestSecurityEventsAndGlobalRulesHTTP(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	a, err := repo.CreateBoard(t.Context(), "securityone", "確認一")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	for _, path := range []string{"/waf-events", "/global-rules", "/api/v1/waf-events", "/api/v1/global-rules"} {
		res, _ := c.request("GET", path, "", nil)
		if res.StatusCode != 401 {
			t.Fatal("anonymous", path, res.StatusCode)
		}
	}
	c.login(adminTestSecret)
	res, page := c.request("GET", "/global-rules", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, `name="minutes" value="0"`) {
		t.Fatal("new global rule must default to unlimited", res.StatusCode)
	}
	settings := defaultAbuseGuard()
	settings.Rates.Enabled = false
	settings.Similar.Mode = "off"
	settings.Flood.Mode = "off"
	saveGuardSettings(t, c, settings, "security-disable-rate-0001")
	edit := globalRuleEdit{Action: "add", Field: "body", Operator: "contains", Value: "禁止広告", Operation: "both", Mode: "reject", Minutes: 10080}
	v := postGlobalEdit(t, c, edit)
	if len(v.Settings.Rules) != 1 {
		t.Fatal(v)
	}
	// 規制追加後に新設した板も必ず適用される。
	b, err := repo.CreateBoard(t.Context(), "securitytwo", "確認二")
	if err != nil {
		t.Fatal(err)
	}
	for _, board := range []BoardInfo{a, b} {
		server := formServer(t, repo, siteID(repo.site.State()), board.ID, true)
		fields := url.Values{"bbs": {board.Key}, "subject": {"通常の話題"}, "MESSAGE": {"禁止広告の本文"}, "oimo_request_id": {domain.NewID().String()}}
		got, err := sendForm(server, fields)
		if err != nil || got.Accepted {
			t.Fatal("global bypass", got, err)
		}
		fields.Set("MESSAGE", "普通の本文")
		fields.Set("oimo_request_id", domain.NewID().String())
		got, err = sendForm(server, fields)
		if err != nil || !got.Accepted {
			t.Fatal("normal rejected", got, err)
		}
		server.Close()
	}
	repo.securityLog.Add(securitylog.Event{At: time.Now(), Source: "similar", Reason: "類似本文の連投", Body: "禁止広告の本文<script>alert(1)</script>", MatchBody: "禁止広告の本文"})
	repo.securityLog.Add(securitylog.Event{At: time.Now(), Source: "similar", Reason: "類似本文の連投", Body: "表示しない過去の確認用ログ", Dummy: true})
	res, body := c.request("GET", "/waf-events", "", nil)
	if res.StatusCode != 200 || strings.Contains(body, "確認用ダミー") || strings.Contains(body, "表示しない過去の確認用ログ") || strings.Contains(body, `name="dummy"`) || !strings.Contains(body, `class="security-table"`) || !strings.Contains(body, "NGワードを設定") || strings.Contains(body, "<script>alert(1)</script>") {
		t.Fatal("events page", res.StatusCode, body)
	}
	res, apiBody := c.request("GET", "/api/v1/waf-events", "", nil)
	if res.StatusCode != 200 || strings.Contains(apiBody, "表示しない過去の確認用ログ") || strings.Contains(apiBody, `"Dummy"`) {
		t.Fatal("API exposed dummy logs", res.StatusCode, apiBody)
	}
	view, err := repo.securityLog.View(time.Now())
	if err != nil || view.Rejected != 2 || view.Detected != 1 || view.Groups != 3 {
		t.Fatal("counts", view, err)
	}
	eventID := ""
	for _, row := range view.Rows {
		if row.Source == "similar" {
			eventID = row.ID
		}
	}
	res, body = c.request("GET", "/global-rules?event="+url.QueryEscape(eventID), "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "禁止広告の本文") || !strings.Contains(body, `name="minutes" value="0"`) {
		t.Fatal("log to rule", res.StatusCode, body)
	}
	// CSRF不正、未知query、パストラバーサルにより保存/ログ閲覧を迂回できない。
	for _, path := range []string{"/waf-events?dummy=only", "/api/v1/waf-events?dummy=only", "/waf-events?dummy=only&dummy=exclude", "/waf-events?unknown=x", "/global-rules?event=../../etc/passwd"} {
		res, _ = c.request("GET", path, "", nil)
		if res.StatusCode == 200 {
			t.Fatal("invalid query", path)
		}
	}
	raw, _ := json.Marshal(edit)
	res, _ = c.request("POST", "/api/v1/global-rules", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {"invalid"}})
	if res.StatusCode != 403 {
		t.Fatal("CSRF", res.StatusCode)
	}
	// snapshotでも全板規制が読め、最低readerを下げた状態は起動検査で拒否する。
	state := repo.site.State()
	header := store.Header{Kind: 1, Owner: siteID(state), Generation: 2, BaseSeq: uint64(state.Seq)}
	snapshot, err := store.EncodeControlSnapshot(header, state, 6, snapshotSiteValue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.DecodeControlSnapshot(snapshot, header, snapshotSiteValue); err != nil {
		t.Fatal(err)
	}
	c.server.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("reopen", err)
	}
	c = newAdminClient(t, repo)
	c.login(adminTestSecret)
	view, err = repo.securityLog.View(time.Now())
	if err != nil || view.Rejected != 2 || view.Detected != 1 || view.Groups != 3 {
		t.Fatal("restart counts", view, err)
	}
	postGlobalEdit(t, c, globalRuleEdit{Action: "revoke", ID: v.Settings.Rules[0].ID.String()})
	server := formServer(t, repo, siteID(repo.site.State()), a.ID, true)
	defer server.Close()
	got, err := sendForm(server, url.Values{"bbs": {a.Key}, "subject": {"解除後"}, "MESSAGE": {"禁止広告"}, "oimo_request_id": {domain.NewID().String()}})
	if err != nil || !got.Accepted {
		t.Fatal("revoked", got, err)
	}
}

func TestSecuritySimilarLogHasBothBodies(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	a, err := repo.CreateBoard(t.Context(), "similarlog", "比較")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	settings := defaultAbuseGuard()
	settings.Rates.Enabled = false
	settings.Similar.MatchPosts = 1
	settings.Similar.Mode = "observe"
	settings.Flood.Mode = "off"
	saveGuardSettings(t, c, settings, "security-similar-log-001")
	server := formServer(t, repo, siteID(repo.site.State()), a.ID, true)
	defer server.Close()
	fields := url.Values{"bbs": {a.Key}, "subject": {"同じ文"}, "MESSAGE": {"何度も繰り返し投稿する宣伝の長い文章です"}, "oimo_request_id": {domain.NewID().String()}}
	for range 2 {
		fields.Set("oimo_request_id", domain.NewID().String())
		got, err := sendForm(server, fields)
		if err != nil || !got.Accepted {
			t.Fatal(got, err)
		}
	}
	view, err := repo.securityLog.View(time.Now())
	if err != nil || view.Detected != 1 || view.Rows[0].Body == "" || view.Rows[0].MatchBody == "" {
		t.Fatal("comparison", view, err)
	}
	settings.Similar.Mode = "reject"
	saveGuardSettings(t, c, settings, "security-similar-log-002")
	fields.Set("oimo_request_id", domain.NewID().String())
	got, err := sendForm(server, fields)
	if err != nil || got.Accepted {
		t.Fatal("reject", got, err)
	}
	view, err = repo.securityLog.View(time.Now())
	if err != nil || view.Detected != 1 || view.Rejected != 1 {
		t.Fatal("shared list", view, err)
	}
}
