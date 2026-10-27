// 実HTTPの監査一覧、固定ページ、秘密非表示、フィルタ、再起動を確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func (c *adminClient) audit(query string) (*http.Response, AuditPage, string) {
	c.t.Helper()
	path := "/api/v1/audit"
	if query != "" {
		path += "?" + query
	}
	res, body := c.request("GET", path, "", nil)
	var v struct {
		Data AuditPage `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &v); e != nil {
		c.t.Fatal(e)
	}
	return res, v.Data, body
}
func TestAdminAuditPagingPrivacyAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if res, _, _ := client.audit(""); res.StatusCode != 401 {
		t.Fatal("anonymous audit")
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _, _ := client.audit("limit=1")
	if res.StatusCode != 200 {
		t.Fatal("initial audit", res.StatusCode)
	}
	// 値や対象IPが確定controlに存在しても、要約へは流出させない。
	siteRes, _ := client.site()
	siteHeaders := http.Header{"Content-Type": {"application/json"}, "If-Match": {siteRes.Header.Get("ETag")}, "X-Csrf-Token": {siteRes.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"audit-site-update-0001"}}
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"PRIVATE_SETTING_SENTINEL"}`, siteHeaders)
	if res.StatusCode != 200 {
		t.Fatal("site update")
	}
	rulesRes, _ := client.rules(board.ID)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {rulesRes.Header.Get("ETag")}, "X-Csrf-Token": {rulesRes.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"audit-rule-create-001"}}
	raw, _ := json.Marshal(AdminRuleInput{"192.0.2.123", []string{"reply"}, 60, "manual", nil, nil, nil, nil})
	res, _ = client.request("POST", "/api/v1/boards/"+board.ID.String()+"/rules", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("rule")
	}
	res, first, body := client.audit("limit=1")
	if res.StatusCode != 200 || first.Next == "" || first.Total < 4 {
		t.Fatal("first page", res.StatusCode, first)
	}
	for _, secret := range []string{"PRIVATE_SETTING_SENTINEL", "192.0.2.123", "audit-rule-create-001", "request_hmac", "salt_base64", "digest_base64", adminTestSecret} {
		if strings.Contains(body, secret) {
			t.Fatal("audit leaked", secret)
		}
	}
	// APIだけでなく日別保存にも秘密をコピーしない。
	if e = filepath.WalkDir(filepath.Join(cfg.DataDir, "audit"), func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		// 共通control envelopeのnull欄は値を持たない。非nullのHMACは拒否する。
		content := strings.ReplaceAll(string(raw), `"request_hmac":null`, "")
		content = strings.ReplaceAll(content, `"request_key_hmac":null`, "")
		content = strings.ReplaceAll(content, `"idempotency_hmac":null`, "")
		for _, secret := range []string{"PRIVATE_SETTING_SENTINEL", "192.0.2.123", "audit-rule-create-001", "request_hmac", "request_key_hmac", "idempotency_hmac", "salt_base64", "digest_base64", adminTestSecret} {
			if strings.Contains(content, secret) {
				t.Fatal("archive leaked", secret)
			}
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// 一覧取得後の変更は次ページへ割り込まない。
	siteRes, _ = client.site()
	siteHeaders.Set("If-Match", siteRes.Header.Get("ETag"))
	siteHeaders.Set("Idempotency-Key", "audit-site-update-0002")
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"later"}`, siteHeaders)
	if res.StatusCode != 200 {
		t.Fatal("later save")
	}
	ids := map[domain.ID]bool{}
	page := first
	for {
		for _, entry := range page.Entries {
			if ids[entry.ID] {
				t.Fatal("duplicate page entry")
			}
			ids[entry.ID] = true
		}
		if page.Next == "" {
			break
		}
		var reply *http.Response
		reply, page, _ = client.audit(url.Values{"cursor": {page.Next}}.Encode())
		if reply.StatusCode != 200 || page.Total != first.Total {
			t.Fatal("unstable page")
		}
	}
	if len(ids) != int(first.Total) {
		t.Fatal("missing page entries")
	}
	res, latest, latestBody := client.audit("")
	if res.StatusCode != 200 || latest.Total != first.Total+1 {
		t.Fatal("new snapshot missing update")
	}
	for _, secret := range []string{"PRIVATE_SETTING_SENTINEL", "192.0.2.123", "audit-site-update-0001", "request_hmac", "salt_base64", "digest_base64"} {
		if strings.Contains(latestBody, secret) {
			t.Fatal("full audit leaked", secret)
		}
	}
	_, boardPage, _ := client.audit(url.Values{"board": {board.ID.String()}, "limit": {"1"}}.Encode())
	if boardPage.Next == "" {
		t.Fatal("filtered page cursor")
	}
	pageRes, pageHTML := client.request("GET", "/audit?"+url.Values{"cursor": {boardPage.Next}}.Encode(), "", nil)
	if pageRes.StatusCode != 200 || !strings.Contains(pageHTML, `name="board" value="`+board.ID.String()+`"`) {
		t.Fatal("page filter lost")
	}
	_, filtered, _ := client.audit(url.Values{"board": {board.ID.String()}, "action": {"rule_create"}}.Encode())
	if filtered.Total != 1 || filtered.Entries[0].Board == nil || *filtered.Entries[0].Board != board.ID {
		t.Fatal("board/action filter")
	}
	actor := filtered.Entries[0].ActorID
	_, actorPage, _ := client.audit(url.Values{"actor": {actor.String()}}.Encode())
	for _, entry := range actorPage.Entries {
		if entry.ActorID == nil || *entry.ActorID != *actor {
			t.Fatal("actor filter")
		}
	}
	res, _, _ = client.audit(url.Values{"cursor": {first.Next + "x"}}.Encode())
	if res.StatusCode != 409 {
		t.Fatal("tampered cursor")
	}
	res, _, _ = client.audit(url.Values{"cursor": {first.Next}, "action": {"rule_revoke"}}.Encode())
	if res.StatusCode != 400 {
		t.Fatal("cursor filter changed")
	}
	other := newAdminClient(t, repo)
	defer other.server.Close()
	if other.login(adminTestSecret) != 303 {
		t.Fatal("second login")
	}
	res, _, _ = other.audit(url.Values{"cursor": {first.Next}}.Encode())
	if res.StatusCode != 409 {
		t.Fatal("cursor crossed session")
	}
	// 同一変更要求の再送は監査件数も増やさない。
	res, _ = client.request("PATCH", "/api/v1/site", `{"name":"later"}`, siteHeaders)
	if res.StatusCode != 200 {
		t.Fatal("retry")
	}
	_, again, _ := client.audit("")
	if again.Total != latest.Total {
		t.Fatal("retry duplicated audit")
	}
	oldIDs := map[domain.ID]bool{}
	for _, entry := range again.Entries {
		oldIDs[entry.ID] = true
	}
	client.server.Close()
	other.server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	_, restored, _ := client.audit("")
	if restored.Total != again.Total {
		t.Fatal("audit lost on restart")
	}
	for _, entry := range restored.Entries {
		if !oldIDs[entry.ID] {
			t.Fatal("audit identity changed")
		}
	}
	res, _, _ = client.audit(url.Values{"cursor": {first.Next}}.Encode())
	if res.StatusCode != 409 {
		t.Fatal("old cursor survived restart")
	}
	res, html := client.request("GET", "/audit?action=rule_create", "", nil)
	if res.StatusCode != 200 || !strings.Contains(html, "投稿規制を登録") || strings.Contains(html, "192.0.2.123") {
		t.Fatal("audit HTML")
	}
}
func TestAuditQueryAndExpiry(t *testing.T) {
	now := time.Now()
	for _, raw := range []string{"limit=0", "limit=201", "limit=01", "limit=1&limit=2", "unknown=x", "actor=wrong", "action=password", "from=bad", "from=" + url.QueryEscape(now.Add(-181*24*time.Hour).Format(time.RFC3339Nano)), "cursor=x&board="} {
		if _, _, e := parseAuditQuery(raw, now); e == nil {
			t.Fatal("bad query accepted", raw)
		}
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	if _, e := repo.CreateBoard(context.Background(), "news", "ニュース"); e != nil {
		t.Fatal(e)
	}
	_, page, _ := client.audit("limit=1")
	if page.Next == "" {
		t.Fatal("cursor")
	}
	repo.mu.Lock()
	for k, v := range repo.auditSnapshots {
		v.expires = now.Add(-time.Second)
		repo.auditSnapshots[k] = v
	}
	repo.mu.Unlock()
	res, _, _ := client.audit(url.Values{"cursor": {page.Next}}.Encode())
	if res.StatusCode != 409 {
		t.Fatal("expiry")
	}
	// queryを許可するのは監査GETだけ。既存管理変更の入口を広げない。
	res, _ = client.request("GET", "/api/v1/site?limit=1", "", nil)
	if res.StatusCode != 403 {
		t.Fatal("query leaked to other route")
	}
}

func TestAuditTimeWindowAndSnapshotCapacity(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if _, e := repo.CreateBoard(context.Background(), "news", "ニュース"); e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, all, _ := client.audit("")
	at, e := time.Parse(time.RFC3339Nano, all.Entries[0].Committed)
	if e != nil {
		t.Fatal(e)
	}
	query := url.Values{"from": {at.Format(time.RFC3339Nano)}, "to": {at.Add(time.Nanosecond).Format(time.RFC3339Nano)}}
	res, one, _ := client.audit(query.Encode())
	if res.StatusCode != 200 || one.Total != 1 || one.Entries[0].ID != all.Entries[0].ID {
		t.Fatal("inclusive start", one)
	}
	query.Set("from", at.Add(-time.Nanosecond).Format(time.RFC3339Nano))
	query.Set("to", at.Format(time.RFC3339Nano))
	_, none, _ := client.audit(query.Encode())
	if none.Total != 0 {
		t.Fatal("exclusive end")
	}
	var first AuditPage
	for i := 0; i < 8; i++ {
		res, page, _ := client.audit("limit=1")
		if res.StatusCode != 200 || page.Next == "" {
			t.Fatal("snapshot capacity", i, res.StatusCode)
		}
		if i == 0 {
			first = page
		}
	}
	res, _, body := client.audit("limit=1")
	if res.StatusCode != 503 || !strings.Contains(body, "AUDIT_SNAPSHOTS_FULL") {
		t.Fatal("snapshot overflow", res.StatusCode)
	}
	// 上限到達で既存cursorを勝手に追い出さない。
	res, _, _ = client.audit(url.Values{"cursor": {first.Next}}.Encode())
	if res.StatusCode != 200 {
		t.Fatal("live snapshot evicted")
	}
}
