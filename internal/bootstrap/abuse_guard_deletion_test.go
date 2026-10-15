// 削除確定と再起動の双方で、削除済み本文を類似判定に使わないことを検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/postcapture"
	"testing"
)

func TestAbuseGuardDeletedBodyExcludedAfterRestart(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "deletedguard", "削除検査")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	c.login(adminTestSecret)
	v := defaultAbuseGuard()
	v.Rates.Enabled = false
	v.Similar.Mode = "reject"
	v.Similar.MatchPosts = 1
	v.Flood.Mode = "off"
	saveGuardSettings(t, c, v, "deleted-guard-save-0001")
	server := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer func() { server.Close() }()
	fields := url.Values{"bbs": {"deletedguard"}, "subject": {"投稿"}, "MESSAGE": {"削除後に比較索引から消える本文です。"}, "oimo_request_id": {"deleted-guard-post-0001"}}
	first, err := sendForm(server, fields)
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, first.Key)
	res, _ := c.request("GET", path, "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"deleted-guard-redact-0001"}}
	raw, _ := json.Marshal(AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}})
	res, body := c.request("POST", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	repo.guard.mu.Lock()
	count := len(repo.guard.entries)
	repo.guard.mu.Unlock()
	if count != 0 {
		t.Fatal("deleted body retained", count)
	}
	server.Close()
	c.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = formServer(t, repo, siteID(repo.site.State()), board.ID)
	fields.Set("oimo_request_id", "deleted-guard-repost-0001")
	result, err := sendForm(server, fields)
	if err != nil || !result.Accepted {
		t.Fatal("deleted body restored", result, err)
	}
}
