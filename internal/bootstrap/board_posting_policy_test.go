// 稼働中設定変更、板間の分離、無効期間の履歴維持、正本復旧を実際の管理・投稿経路で検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func saveBoardRates(t *testing.T, c *adminClient, id domain.ID, rates AdminRateSettings, key string) AdminBoard {
	t.Helper()
	res, b := c.board(id.String())
	edit := b.Settings
	edit.Rates = &rates
	edit.Anonymous = &AdminAnonymousSettings{Mode: "required"}
	raw, _ := json.Marshal(edit)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {key}}
	res, body := c.request("PATCH", "/api/v1/boards/"+id.String()+"/settings", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("rates save", res.StatusCode, body)
	}
	savedETag := res.Header.Get("ETag")
	res, body = c.request("PATCH", "/api/v1/boards/"+id.String()+"/settings", string(raw), headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != savedETag {
		t.Fatal("rates retry", res.StatusCode, body)
	}
	_, b = c.board(id.String())
	return b
}
func TestBoardPostingRatesOnlineHistoryAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	other, e := repo.CreateBoard(context.Background(), "other", "別板")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	server := formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	defer func() { server.Close() }()
	fields := url.Values{"bbs": {"news"}, "subject": {"投稿"}, "MESSAGE": {"本文"}, "oimo_request_id": {"rate-legacy-create-0001"}}
	result, e := sendForm(server, fields)
	if e != nil || !result.Accepted {
		t.Fatal("legacy post", result, e)
	}
	rates := AdminRateSettings{true, 10, 1, 3600, 1, 1}
	saveBoardRates(t, c, board.ID, rates, "rates-online-enable-001")
	if repo.stopped || repo.admission == nil || repo.anonymous == nil {
		t.Fatal("server not resumed")
	}
	fields.Set("oimo_request_id", "rate-active-create-0001")
	result, e = sendForm(server, fields)
	if e != nil || !result.Accepted {
		t.Fatal("first active post", result, e)
	}
	fields.Set("oimo_request_id", "rate-limited-create-001")
	result, e = sendForm(server, fields)
	if e != nil || result.Accepted {
		t.Fatal("interval bypass", result, e)
	}
	rates.Enabled = false
	saveBoardRates(t, c, board.ID, rates, "rates-online-disable-01")
	fields.Set("oimo_request_id", "rate-disabled-create-01")
	result, e = sendForm(server, fields)
	if e != nil || !result.Accepted {
		t.Fatal("disabled post", result, e)
	}
	rates.Enabled = true
	saveBoardRates(t, c, board.ID, rates, "rates-online-reenable-1")
	fields.Set("oimo_request_id", "rate-reenabled-create-1")
	result, e = sendForm(server, fields)
	if e != nil || result.Accepted {
		t.Fatal("history reset", result, e)
	}
	_, untouched := c.board(other.ID.String())
	if (untouched.Settings.Rates == nil || untouched.Settings.Rates.Enabled) || untouched.Settings.Anonymous == nil || untouched.Settings.Anonymous.Mode != "required" {
		t.Fatal("other board edited")
	}
	otherForm := formServer(t, repo, siteID(repo.site.State()), other.ID, true)
	otherFields := url.Values{"bbs": {"other"}, "subject": {"別板"}, "MESSAGE": {"本文"}, "oimo_request_id": {"rate-other-create-0001"}}
	result, e = sendForm(otherForm, otherFields)
	otherForm.Close()
	if e != nil || !result.Accepted {
		t.Fatal("other board blocked", result, e)
	}
	history, e := repo.rateHistory()
	if e != nil || len(history) != 4 {
		t.Fatal("accepted history", len(history), e)
	}
	server.Close()
	c.server.Close()
	// snapshot世代へ切替えて旧制御WALの遷移に頼らず同じ設定履歴を復旧する。
	if _, e = repo.EnableControlSnapshots(context.Background()); e != nil {
		t.Fatal(e)
	}
	candidate := filepath.Join(candidateParent(t), "rates-candidate")
	if _, e = repo.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal("snapshot prepare", e)
	}
	repo.Close()
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal("snapshot activate", e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recovery", e)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login after restart")
	}
	_, current := c.board(board.ID.String())
	if current.Settings.Rates == nil || *current.Settings.Rates != rates {
		t.Fatal("settings lost")
	}
	server = formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	fields.Set("oimo_request_id", "rate-restart-create-001")
	result, e = sendForm(server, fields)
	if e != nil || result.Accepted {
		t.Fatal("restart reset limit", result, e)
	}
}
func TestBoardRatesCarryDebtAcrossIntervalAndBurstChanges(t *testing.T) {
	now := time.Now()
	a := &admission{policy: initialAdmission(now), limits: abuse.NewLimiter(100)}
	board, other := domain.NewID(), domain.NewID()
	ip := netip.MustParseAddr("192.0.2.1")
	for range 3 {
		ticket, _, _, e := a.reserve(board, ip, false, func() time.Time { return now })
		if e != nil {
			t.Fatal(e)
		}
		a.limits.Commit(ticket)
	}
	rates := AdminRateSettings{true, 10, 4, 600, 1, 6}
	if e := a.applyBoardRates(board, rates, now); e != nil {
		t.Fatal(e)
	}
	ticket, _, _, e := a.reserve(board, ip, false, func() time.Time { return now })
	if e != nil {
		t.Fatal("burst increase should add exactly one", e)
	}
	a.limits.Commit(ticket)
	_, _, _, e = a.reserve(board, ip, false, func() time.Time { return now })
	var limited *abuse.RateLimited
	if !errors.As(e, &limited) || limited.RetryAfter != 10 {
		t.Fatal("consumption lost", e)
	}
	ticket, _, _, e = a.reserve(other, ip, false, func() time.Time { return now })
	if e != nil {
		t.Fatal("another board", e)
	}
	a.limits.Commit(ticket)
}

func TestBoardRatesSaveFailureKeepsPreviousPolicy(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, e := repo.CreateBoard(context.Background(), "news", "保存失敗")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	rates := AdminRateSettings{true, 10, 1, 600, 1, 6}
	saveBoardRates(t, c, board.ID, rates, "rate-before-failure-001")
	res, current := c.board(board.ID.String())
	changed := rates
	changed.ReplySeconds = 20
	edit := current.Settings
	edit.Rates = &changed
	raw, _ := json.Marshal(edit)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"rate-failed-save-0001"}}
	if e := repo.boards[board.ID].Close(); e != nil {
		t.Fatal(e)
	}
	res, body := c.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), headers)
	if res.StatusCode != 503 || !repo.posting[board.ID].stopped {
		t.Fatal("uncertain save resumed", res.StatusCode, body)
	}
	if repo.posting[board.ID].postingPolicy.Rates != rates {
		t.Fatal("failed policy published")
	}
	c.server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if repo.posting[board.ID].postingPolicy.Rates != rates {
		t.Fatal("failed policy recovered")
	}
}

// 独立した期待値のfixtureと、不正なAPI形を実際の検査器へ渡す。
func TestBoardRateSettingsFixtureAndStrictInput(t *testing.T) {
	var fixture struct {
		Schema string `json:"schema"`
		Cases  []struct {
			Name     string            `json:"name"`
			Settings AdminRateSettings `json:"settings"`
			Valid    bool              `json:"valid"`
		} `json:"cases"`
	}
	raw, e := os.ReadFile("../../docs/design/fixtures/board-posting-rates.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = strictjson.Decode(raw, &fixture); e != nil {
		t.Fatal(e)
	}
	if fixture.Schema != "board-posting-rates-v1" || len(fixture.Cases) != 10 {
		t.Fatal("fixture shape")
	}
	for _, v := range fixture.Cases {
		t.Run(v.Name, func(t *testing.T) {
			if (v.Settings.validate() == nil) != v.Valid {
				t.Fatal("unexpected validity")
			}
		})
	}
	base, _ := json.Marshal(AdminBoardEdit{Input: defaultBoardSettings().Input, Create: "anyone", Reply: "anyone"})
	for _, extra := range []string{`,"rates":null`, `,"rates":{"enabled":true}`, `,"rates":{"enabled":true,"reply_seconds":1,"reply_burst":3,"create_seconds":600,"create_burst":1,"create_window_limit":6,"unknown":1}`, `,"rates":{"enabled":true,"enabled":false,"reply_seconds":1,"reply_burst":3,"create_seconds":600,"create_burst":1,"create_window_limit":6}`} {
		var edit AdminBoardEdit
		invalid := append(append([]byte{}, base[:len(base)-1]...), []byte(extra+"}")...)
		if strictjson.Decode(invalid, &edit) == nil {
			t.Fatal("invalid rates shape accepted", extra)
		}
	}
}

func TestBoardRatesConcurrentReservationsAndReconfiguration(t *testing.T) {
	now := time.Now()
	a := &admission{policy: initialAdmission(now), limits: abuse.NewLimiter(100)}
	owner, other := domain.NewID(), domain.NewID()
	ip := netip.MustParseAddr("192.0.2.1")
	failures := make(chan error, 300)
	var wg sync.WaitGroup
	for _, board := range []domain.ID{owner, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				ticket, _, _, e := a.reserve(board, ip, false, func() time.Time { return now })
				var limited *abuse.RateLimited
				if e != nil {
					if !errors.As(e, &limited) {
						failures <- e
					}
					continue
				}
				if e = a.limits.Commit(ticket); e != nil {
					failures <- e
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 100 {
			rates := AdminRateSettings{Enabled: i%2 == 0, ReplySeconds: 10, ReplyBurst: 3, CreateSeconds: 600, CreateBurst: 1, CreateWindow: 6}
			if e := a.applyBoardRates(owner, rates, now); e != nil && !errors.Is(e, abuse.ErrRateUncertain) {
				failures <- e
			}
		}
	}()
	wg.Wait()
	close(failures)
	for e := range failures {
		t.Error(e)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ratesForBoard(other) != defaultRateSettings() {
		t.Fatal("other board reconfigured")
	}
}

func TestBoardRatesApplyToTokenAcrossIPs(t *testing.T) {
	now := time.Now()
	a := &admission{policy: initialAdmission(now), limits: abuse.NewLimiter(100), anonymous: &AnonymousPolicy{ReplyRule: domain.NewID(), CreateRule: domain.NewID()}}
	board, token := domain.NewID(), domain.NewID()
	rates := AdminRateSettings{true, 10, 1, 600, 1, 6}
	if e := a.applyBoardRates(board, rates, now); e != nil {
		t.Fatal(e)
	}
	firstIP, secondIP := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1")
	ticket, _, _, e := a.reserveAnonymous(board, firstIP, false, func() time.Time { return now }, token)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.limits.Commit(ticket); e != nil {
		t.Fatal(e)
	}
	_, _, _, e = a.reserveAnonymous(board, secondIP, false, func() time.Time { return now }, token)
	var limited *abuse.RateLimited
	if !errors.As(e, &limited) || limited.RetryAfter != 10 {
		t.Fatal("token interval ignored across IPs", e)
	}
	// token不足時に新しいIPの枠を部分消費していない。
	ticket, _, _, e = a.reserve(board, secondIP, false, func() time.Time { return now })
	if e != nil {
		t.Fatal("partial IP consumption", e)
	}
	if e = a.limits.Commit(ticket); e != nil {
		t.Fatal(e)
	}
}
