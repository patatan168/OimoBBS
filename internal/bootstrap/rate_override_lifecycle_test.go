// HTTP管理・Cookie/cap併用・指定除外・解除・正本復旧の追加枠を確認する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestRateOverrideLifecycle(t *testing.T) {
	cfg, r, board := anonymousAdminFixture(t, "required")
	defer func() { r.Close() }()
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("admin login")
	}
	cap, secret := createTestCap(t, r, c, board, []string{"create", "post"})
	path := "/api/v1/boards/" + board.String() + "/rules"
	save := func(input AdminRuleInput) AdminRule {
		t.Helper()
		res, _ := c.rules(board)
		raw, _ := json.Marshal(input)
		res, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
		if res.StatusCode != 200 {
			t.Fatal("save override", res.StatusCode, body)
		}
		return ruleResponse(t, body)
	}
	rate := save(AdminRuleInput{Target: "制限", Operations: []string{"reply"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"body", "contains", "rate_override"}, Rate: &AdminRateOverride{3600, 1, 1}})
	server, request, _ := anonymousHTTP(t, r, siteID(r.site.State()))
	defer func() { server.Close() }()
	post := url.Values{"bbs": {"news"}, "FROM": {"運営"}, "mail": {"sage #cap:" + cap.ID.String() + ":" + secret}, "subject": {"追加枠確認"}, "MESSAGE": {"初回"}, "oimo_request_id": {"rate-create-request-001"}}
	request("POST", "/test/bbs.cgi", post)
	_, body := request("POST", "/test/bbs.cgi", post)
	rows, e := r.rateHistory()
	if e != nil || len(rows) != 1 || strings.Contains(body, "ERROR:") {
		t.Fatal("create", e, body)
	}
	key := strconv.FormatUint(rows[0].key, 10)
	post.Del("subject")
	post.Set("key", key)
	post.Set("MESSAGE", "制限 一回")
	post.Set("oimo_request_id", "rate-first-request-001")
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if strings.Contains(body, "ERROR:") || len(rows) != 2 || len(rows[1].record.Keys) != 5 || rows[1].record.Schema != postcapture.Schema || len(rows[1].record.Overrides) != 1 || rows[1].record.Overrides[0] != rate.ID {
		t.Fatal("additional proof", body, rows)
	}
	checkRateCaptureTampering(t, r.posting[board])
	// 受理済み再送は追加枠を二重課金しない。
	request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if len(rows) != 2 {
		t.Fatal("retry charged")
	}
	post.Set("MESSAGE", "制限 二回")
	post.Set("oimo_request_id", "rate-blocked-request-001")
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if !strings.Contains(body, "ERROR:") || len(rows) != 2 {
		t.Fatal("quota bypass", body)
	}
	server.Close()
	c.server.Close()
	r.Close()
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("restore override", e)
	}
	c = newAdminClient(t, r)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	server, request, _ = anonymousHTTP(t, r, siteID(r.site.State()))
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if !strings.Contains(body, "ERROR:") || len(rows) != 2 {
		t.Fatal("restart reset quota", body)
	}
	// 許可は追加枠だけを除き、通常3枠とCookie枠を維持する。
	allow := save(AdminRuleInput{Target: "例外", Operations: []string{"reply"}, Minutes: 60, Reason: "manual", Match: &AdminRuleMatch{"body", "contains", "allow_rule_ids"}, Allowed: []domain.ID{rate.ID}})
	post.Set("MESSAGE", "制限 例外")
	post.Set("oimo_request_id", "rate-exception-request-001")
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	rows, _ = r.rateHistory()
	if strings.Contains(body, "ERROR:") || len(rows) != 3 || len(rows[2].record.Keys) != 4 {
		t.Fatal("scoped rate exception", body)
	}
	_, list := c.rules(board)
	for _, rule := range list.Rules {
		if rule.ID == allow.ID {
			allow = rule
		}
	}
	res, body := c.request("POST", path+"/"+allow.ID.String()+"/revoke", "{}", http.Header{"Content-Type": {"application/json"}, "If-Match": {allow.ETag()}, "X-CSRF-Token": {allow.RevokeCSRF}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("revoke exception", res.StatusCode, body)
	}
	_, list = c.rules(board)
	for _, rule := range list.Rules {
		if rule.ID == rate.ID {
			rate = rule
		}
	}
	res, body = c.request("POST", path+"/"+rate.ID.String()+"/revoke", "{}", http.Header{"Content-Type": {"application/json"}, "If-Match": {rate.ETag()}, "X-CSRF-Token": {rate.RevokeCSRF}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal("revoke override", res.StatusCode, body)
	}
	server.Close()
	c.server.Close()
	r.Close()
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("revoked history restore", e)
	}
	// snapshot切替でも停止時刻と過去の除外判断を保持する。
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "rate-candidate")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	r.Close()
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("snapshot restore", e)
	}
	r.Close()
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	backup, keys, work := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if _, e = CaptureOfflineBackup(context.Background(), cfg, backup); e != nil {
		t.Fatal("rate capture", e)
	}
	if _, e = ExportBackupKeys(context.Background(), cfg, backup, keys); e != nil {
		t.Fatal("rate keys", e)
	}
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	report, e := VerifyBackupReplay(context.Background(), backup, keys, work)
	if e != nil || !report.Replayed || report.RestoreReady {
		t.Fatal("rate replay", report, e)
	}
}
