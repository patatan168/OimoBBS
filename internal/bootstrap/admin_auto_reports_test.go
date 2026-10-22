// 24時間集計・成立票の管理閲覧・永久規制の再起動と解除を実HTTPで検証する。
package bootstrap

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
)

func TestAutoReportTwentyFourHourBoundary(t *testing.T) {
	if autoReportWindow != 24*time.Hour || autoReportStop != 10*time.Minute {
		t.Fatal("window or stop duration")
	}
	at := domain.Time(48 * time.Hour)
	vote := func(id byte, elapsed time.Duration) autoReportVote {
		return autoReportVote{Operation: domain.ID{id}, Reporter: domain.Hash{id}, IP: domain.Hash{id}, At: at + domain.Time(elapsed)}
	}
	votes, _ := collectAutoReport(nil, vote(1, 0))
	votes, _ = collectAutoReport(votes, vote(2, 12*time.Hour))
	_, ready := collectAutoReport(votes, vote(3, 24*time.Hour-time.Nanosecond))
	if !ready {
		t.Fatal("three votes within 24 hours")
	}
	votes, ready = collectAutoReport(votes, vote(3, 24*time.Hour))
	if ready || len(votes) != 2 {
		t.Fatal("24 hour old vote must expire")
	}
}

func TestAdminAutoReportsMixedVotesPermanentAndRecovery(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	if _, err := repo.CreateBoard(t.Context(), "report", "通報"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := evidence.NewHTTPObserver(site, domain.NewID(), "review-test")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(repo.SiteWebHandler(obs))
	server.Config.ConnContext = obs.ConnContext
	server.Start()
	defer server.Close()
	victim := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, "127.121.0.1")
	if body := victim.post(t, "news", "", "REVIEW-TARGET <script>bad()</script>", "review-target-create"); !strings.Contains(body, "投稿を受け付けました") {
		t.Fatal("target", body)
	}
	thread := strings.Split(victim.request(t, "/news/subject.txt", nil), ".dat<>")[0]
	for i := 0; i < 3; i++ {
		c := newAutoReportHTTPClient(t, server.URL, cfg.Public.BaseURL, fmt.Sprintf("127.122.0.%d", i+1))
		key, body := thread, fmt.Sprintf(">>1 !report PUBLIC-REVIEW-REASON-%d", i)
		if i == 0 {
			key = "1"
			body = "対象URL：" + cfg.Public.BaseURL + "/test/read.cgi/news/" + thread + "/1/\n理由：PRIVATE-REVIEW-REASON"
		}
		if result := c.post(t, "news", key, body, fmt.Sprintf("review-vote-number-%d", i)); !strings.Contains(result, "投稿を受け付けました") {
			t.Fatal("vote", result)
		}
	}
	server.Close()
	// 成立票の参照は再起動後にも残る。
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	c := newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, list := c.request("GET", "/auto-reports", "", nil)
	if res.StatusCode != 200 || !strings.Contains(list, "一時停止中") || strings.Contains(list, "PRIVATE-REVIEW-REASON") {
		t.Fatal("list", res.StatusCode)
	}
	var stop denialRule
	_, err = repo.posting[owner].worker.Submit(t.Context(), func() (any, error) {
		for _, entry := range repo.posting[owner].denials {
			if len(entry.rule.Reports) == 3 {
				stop = entry.rule
			}
		}
		return nil, nil
	})
	if err != nil || stop.ID == (domain.ID{}) {
		t.Fatal("durable three vote references", err)
	}
	path := fmt.Sprintf("/auto-reports/%s/%s", owner, stop.ID)
	res, page := c.request("GET", path, "", nil)
	if res.StatusCode != 200 || strings.Contains(page, "PRIVATE-REVIEW-REASON") || !strings.Contains(page, "/inspect\"") {
		t.Fatal("GET must not disclose originals", res.StatusCode)
	}
	reauthPath := "/reauth?" + url.Values{"return_to": {path}}.Encode()
	if res, returnPage := c.request("GET", reauthPath, "", nil); res.StatusCode != 200 || !strings.Contains(returnPage, reauthPath) || !strings.Contains(returnPage, "自動停止・通報確認") {
		t.Fatal("reauth return path")
	}
	preauth := postManagementFields(t, page, path+"/inspect")
	if res, body := c.request("POST", path+"/inspect", preauth.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 200 || !strings.Contains(body, "PRIVATE-REVIEW-REASON") || !strings.Contains(body, "PUBLIC-REVIEW-REASON-1") || !strings.Contains(body, "REVIEW-TARGET") {
		t.Fatal("inspection without reauth", res.StatusCode)
	}
	regulation := postManagementFields(t, page, path+"/rule")
	regulation.Set("duration", "permanent")
	regulation.Set("minutes", "")
	regulation.Set("confirm", "yes")
	if res, _ := c.request("POST", path+"/rule", regulation.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 303 || res.Header.Get("Location") != reauthPath {
		t.Fatal("regulation still requires reauth", res.StatusCode)
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	_, page = c.request("GET", path, "", nil)
	inspect := postManagementFields(t, page, path+"/inspect")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	bad := postManagementFields(t, page, path+"/inspect")
	bad.Set("csrf", "invalid")
	if res, _ := c.request("POST", path+"/inspect", bad.Encode(), headers); res.StatusCode != 403 {
		t.Fatal("csrf", res.StatusCode)
	}
	res, contents := c.request("POST", path+"/inspect", inspect.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(contents, "PRIVATE-REVIEW-REASON") || !strings.Contains(contents, "PUBLIC-REVIEW-REASON-1") || !strings.Contains(contents, "PUBLIC-REVIEW-REASON-2") || !strings.Contains(contents, "REVIEW-TARGET") || strings.Contains(contents, "<script>bad()</script>") || strings.Contains(contents, "127.122.") {
		t.Fatal("contents", res.StatusCode, contents)
	}
	if strings.Count(contents, "REVIEW-TARGET") != 1 || strings.Count(contents, "通報されたレスの内容") != 1 || strings.Count(contents, `<article class="card">`) != 3 {
		t.Fatal("target should appear once with three separate reports")
	}
	// 公開から削除しても、追加権限と監査を経た原本閲覧では判断材料を確認できる。
	postBase := fmt.Sprintf("/boards/%s/threads/%s/posts", owner, thread)
	_, postPage := c.request("GET", postBase+"/1", "", nil)
	deletion := postManagementFields(t, postPage, postBase+"/1/delete")
	deletion.Set("confirm", "yes")
	if res, result := c.request("POST", postBase+"/1/delete", deletion.Encode(), headers); res.StatusCode != 303 {
		t.Fatal("redact", res.StatusCode, result)
	}
	_, postPage = c.request("GET", postBase+"/1", "", nil)
	if strings.Contains(postPage, "REVIEW-TARGET") {
		t.Fatal("redacted public content reappeared")
	}
	inspect = postManagementFields(t, contents, path+"/inspect")
	res, contents = c.request("POST", path+"/inspect", inspect.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(contents, "REVIEW-TARGET") {
		t.Fatal("redacted original unavailable", res.StatusCode)
	}
	form := postManagementFields(t, contents, path+"/rule")
	form.Set("duration", "permanent")
	form.Set("minutes", "")
	form.Set("confirm", "yes")
	res, result := c.request("POST", path+"/rule", form.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("permanent rule", res.StatusCode, result)
	}
	// 同じ要求の再送は追加規制を作らない。
	if res, result = c.request("POST", path+"/rule", form.Encode(), headers); res.StatusCode != 303 {
		t.Fatal("retry", res.StatusCode, result)
	}
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("permanent restart", err)
	}
	var permanent denialRule
	_, err = repo.posting[owner].worker.Submit(t.Context(), func() (any, error) {
		for _, entry := range repo.posting[owner].denials {
			if permanentTokenRule(entry.rule) {
				permanent = entry.rule
			}
		}
		return nil, nil
	})
	if err != nil || permanent.ID == (domain.ID{}) {
		t.Fatal("permanent persistence", err)
	}
	// 30日後も同じ主体を拒否する。
	b := repo.posting[owner]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		subject := new(domain.Hash)
		if e := subject.UnmarshalJSON([]byte(strconv.Quote(permanent.Conditions[0].Value))); e != nil {
			return nil, e
		}
		denied, _, e := b.matchingRules(netip.MustParseAddr("127.121.0.1"), postinput.Input{}, *subject, false, permanent.Starts+domain.Time(31*24*time.Hour))
		if e != nil {
			return nil, e
		}
		if !denied {
			t.Fatal("permanent no longer denies")
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c = newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login after restart")
	}
	_, rules := c.request("GET", "/boards/"+owner.String()+"/rules", "", nil)
	if !strings.Contains(rules, "永久（管理者が解除するまで）") {
		t.Fatal("permanent label")
	}
	revokePath := fmt.Sprintf("/boards/%s/rules/%s/revoke", owner, permanent.ID)
	revoke := postManagementFields(t, rules, revokePath)
	if res, result = c.request("POST", revokePath, revoke.Encode(), headers); res.StatusCode != 303 {
		t.Fatal("revoke", res.StatusCode, result)
	}
}

func TestPermanentRuleRestrictedToAnonymousSubject(t *testing.T) {
	token := AdminRuleInput{Target: domain.Hash{1}.String(), Operations: []string{"create", "reply"}, Minutes: permanentDenyMinutes, Reason: "manual", Match: &AdminRuleMatch{"token", "exact", "deny"}}
	if err := token.validate(); err != nil {
		t.Fatal(err)
	}
	token.Target = "192.0.2.1"
	token.Match = &AdminRuleMatch{"ip", "exact", "deny"}
	if token.validate() == nil {
		t.Fatal("permanent IP rule accepted")
	}
	token.Minutes = maxDenyMinutes + 1
	if token.validate() == nil {
		t.Fatal("duration over 30 days accepted")
	}
}

func TestAdminAutoReportsPermissionBoundaries(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "scope", "対象板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "other", "別板")
	if err != nil {
		t.Fatal(err)
	}
	roles := []struct {
		login, role           string
		boards                []domain.ID
		permissions           []string
		detail, inspect, rule bool
	}{
		{"noextra", "moderator", []domain.ID{board.ID}, []string{}, true, false, false},
		{"moderator", "moderator", []domain.ID{board.ID}, []string{"evidence.manage"}, true, true, false},
		{"outside", "board_admin", []domain.ID{other.ID}, []string{"evidence.manage"}, false, false, false},
		{"boardadmin", "board_admin", []domain.ID{board.ID}, []string{}, true, true, true},
	}
	for _, tc := range roles {
		if _, err = repo.CreateAdministrator(tc.login, tc.login, adminTestSecret, AdministratorAccess{Role: tc.role, Boards: tc.boards, Permissions: tc.permissions, Enabled: true}); err != nil {
			t.Fatal(err)
		}
		repo.Close()
		repo, err = OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			t.Fatal(err)
		}
	}
	id := domain.NewID()
	now := domain.Time(time.Now().UnixNano())
	rule := denialRule{ID: id, Revision: 1, Scope: denialScope{"board", board.ID}, Operations: []string{"create", "reply"}, Conditions: []denialCondition{{"token", "exact", domain.Hash{1}.String(), "deny"}}, Effect: denialEffect{Type: "deny"}, Starts: now, Expires: now + domain.Time(10*time.Minute), Reason: "abuse", Enabled: true}
	policy := defaultReportPolicy()
	rule.ReportPolicy = &policy
	rule.Reports = []autoReportEvidenceRef{{domain.NewID(), autoReportReference{"scope", 1, 1}}, {domain.NewID(), autoReportReference{"scope", 1, 1}}, {id, autoReportReference{"scope", 1, 1}}}
	repo.mu.Lock()
	err = repo.enableDenials(board.ID, true, false, false, false)
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[board.ID]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		if e := appendControl(b.control, "auto_report_stop", []store.Mutation{mutation("board_rule", id.String(), rule, nil)}, []string{id.String()}); e != nil {
			return nil, e
		}
		compiled, e := compileDenial(rule)
		b.denials[id] = compiled
		return nil, e
	})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/auto-reports/%s/%s", board.ID, id)
	for i, tc := range roles {
		t.Run(tc.login, func(t *testing.T) {
			c := newAdminClient(t, repo)
			defer c.server.Close()
			// 管理者ごとに実TCP送信元を分け、共通loopbackの試行上限を累積させない。
			dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("127.123.0.%d", i+1))}}
			transport := &http.Transport{DialContext: dialer.DialContext}
			defer transport.CloseIdleConnections()
			c.server.Client().Transport = transport
			_, loginPage := c.request("GET", "/login", "", nil)
			fields := pageFields(loginPage)
			fields.Set("login", tc.login)
			fields.Set("password", adminTestSecret)
			headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
			if res, _ := c.request("POST", "/login", fields.Encode(), headers); res.StatusCode != 303 {
				t.Fatal("login")
			}
			res, page := c.request("GET", path, "", nil)
			if (res.StatusCode == 200) != tc.detail {
				t.Fatal("scope", res.StatusCode)
			}
			if res.StatusCode == 200 && strings.Contains(page, "PRIVATE-REVIEW") {
				t.Fatal("content in GET")
			}
			session, e := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
			if e != nil {
				t.Fatal(e)
			}
			fields = url.Values{"csrf": {session.CSRF(path + "/inspect")}, "request_id": {domain.NewID().String()}}
			res, _ = c.request("POST", path+"/inspect", fields.Encode(), headers)
			if (res.StatusCode == 200) != tc.inspect {
				t.Fatal("evidence permission", res.StatusCode)
			}
			if !tc.rule {
				if c.reauth(adminTestSecret) != 200 {
					t.Fatal("reauth")
				}
				fields = url.Values{"csrf": {session.CSRF(path + "/rule")}, "request_id": {domain.NewID().String()}, "revision": {b.adminRules().ETag()}, "duration": {"temporary"}, "minutes": {"1440"}, "confirm": {"yes"}}
				res, _ = c.request("POST", path+"/rule", fields.Encode(), headers)
				if res.StatusCode != 403 {
					t.Fatal("regulation permission", res.StatusCode)
				}
			}
		})
	}
}
