// 共通投稿枠の無効化・再有効化・再起動と板別設定による上書き禁止を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/postcapture"
	"testing"
)

func TestAbuseGuardGlobalRatesHistoryAndBoardBoundary(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "global", "共通条件")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "another", "別板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	c.login(adminTestSecret)
	settings := defaultAbuseGuard()
	settings.Similar.Mode, settings.Flood.Mode = "off", "off"
	settings.Rates = AdminRateSettings{true, 10, 1, 3600, 1, 1}
	saveGuardSettings(t, c, settings, "global-rates-enable-0001")
	server := formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	defer func() { server.Close() }()
	fields := url.Values{"bbs": {"global"}, "subject": {"投稿"}, "MESSAGE": {"本文"}, "oimo_request_id": {"global-first-create-0001"}}
	result, err := sendForm(server, fields)
	if err != nil || !result.Accepted {
		t.Fatal("first", result, err)
	}
	fields.Set("oimo_request_id", "global-second-create-0001")
	result, err = sendForm(server, fields)
	if err != nil || result.Accepted {
		t.Fatal("limit", result, err)
	}
	settings.Rates.Enabled = false
	saveGuardSettings(t, c, settings, "global-rates-disable-0001")
	fields.Set("oimo_request_id", "global-disabled-create-0001")
	result, err = sendForm(server, fields)
	if err != nil || !result.Accepted {
		t.Fatal("disabled", result, err)
	}
	settings.Rates.Enabled = true
	saveGuardSettings(t, c, settings, "global-rates-resume-0001")
	fields.Set("oimo_request_id", "global-resumed-create-0001")
	result, err = sendForm(server, fields)
	if err != nil || result.Accepted {
		t.Fatal("debt reset", result, err)
	}
	settings.TokenWaitSeconds = 120
	saveGuardSettings(t, c, settings, "global-cookie-wait-0001")
	res, b := c.board(other.ID.String())
	if b.Settings.Rates == nil || *b.Settings.Rates != settings.Rates || b.Settings.Anonymous.Wait != 120 {
		t.Fatal("other board condition", b.Settings)
	}
	// 旧APIで板だけ待機時間や投稿枠を変更することはできない。
	b.Settings.Anonymous.Wait = 0
	raw, _ := json.Marshal(b.Settings)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"global-board-override-0001"}}
	got, body := c.request("PATCH", "/api/v1/boards/"+other.ID.String()+"/settings", string(raw), headers)
	if got.StatusCode != 422 {
		t.Fatal("board override", got.StatusCode, body)
	}
	otherServer := formServer(t, repo, siteID(repo.site.State()), other.ID, true)
	result, err = sendForm(otherServer, url.Values{"bbs": {"another"}, "subject": {"新規"}, "MESSAGE": {"別板の本文"}, "oimo_request_id": {"global-wait-create-0001"}})
	otherServer.Close()
	if err != nil || result.Accepted {
		t.Fatal("other board wait bypass", result, err)
	}
	// 待機を戻した後も、再起動によって既存投稿枠は補充されない。
	settings.TokenWaitSeconds = 0
	saveGuardSettings(t, c, settings, "global-cookie-reset-0001")
	server.Close()
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	fields.Set("oimo_request_id", "global-restart-create-0001")
	result, err = sendForm(server, fields)
	if err != nil || result.Accepted {
		t.Fatal("restart reset", result, err)
	}
}

// 共通化前に受理した板設定の再送は、現在の共通条件と異なっても元の結果に戻す。
func TestAbuseGuardPriorBoardSettingsRetry(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "priorguard", "旧設定")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	res, b := c.board(board.ID.String())
	rates := AdminRateSettings{false, 10, 1, 3600, 1, 1}
	b.Settings.Rates = &rates
	raw, _ := json.Marshal(b.Settings)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"prior-board-settings-0001"}}
	first, body := c.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), headers)
	if first.StatusCode != 200 {
		t.Fatal(first.StatusCode, body)
	}
	saveGuardSettings(t, c, defaultAbuseGuard(), "prior-global-settings-0001")
	retry, body := c.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), headers)
	if retry.StatusCode != 200 || retry.Header.Get("ETag") != first.Header.Get("ETag") {
		t.Fatal("old retry", retry.StatusCode, body)
	}
}
