// 実HTTPの暗黙再送・pack切替・正本再起動を跨いでも追加枠の消費を保持する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestRateOverrideSurvivesImplicitDedupCompaction(t *testing.T) {
	cfg, r, board := anonymousAdminFixture(t, "required")
	defer func() { _ = r.Close() }()
	c := newAdminClient(t, r)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.rules(board)
	input := AdminRuleInput{Target: "制限", Operations: []string{"create"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"body", "contains", "rate_override"}, Rate: &AdminRateOverride{3600, 1, 1}}
	raw, _ := json.Marshal(input)
	res, body := c.request("POST", "/api/v1/boards/"+board.String()+"/rules", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	c.server.Close()
	server, request, _ := anonymousHTTP(t, r, siteID(r.site.State()))
	post := url.Values{"bbs": {"news"}, "subject": {"暗黙再送"}, "MESSAGE": {"制限 初回"}}
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	before, e := r.rateHistory()
	if e != nil || strings.Contains(body, "ERROR:") || len(before) != 1 || len(before[0].record.Keys) != 5 {
		t.Fatal(before, e, body)
	}
	server.Close()
	b := r.posting[board]
	_, e = b.worker.Submit(context.Background(), func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(before[0].record.At)).Add(31 * time.Second) }
		defer func() { b.clock = time.Now }()
		return b.threads[before[0].key].CompactWithClock(context.Background(), b.clock, 6, true)
	})
	if e != nil {
		t.Fatal(e)
	}
	after, e := r.rateHistory()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("compaction reset rate", after, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	after, e = r.rateHistory()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("restart reset rate", after, e)
	}
	server, request, _ = anonymousHTTP(t, r, siteID(r.site.State()))
	defer server.Close()
	post.Set("subject", "再作成")
	post.Set("MESSAGE", "制限 二回")
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	after, e = r.rateHistory()
	if e != nil || !strings.Contains(body, "ERROR:") || len(after) != 1 {
		t.Fatal("reclaimed retry bypassed quota", after, e, body)
	}
	server.Close()
	if e = r.EnablePublicBodyReclamation(context.Background()); e != nil {
		t.Fatal(e)
	}
	hideBodyFixture(t, r, board, before[0].key)
	if e = r.ReclaimPublicBodies(context.Background(), 8); e != nil {
		t.Fatal(e)
	}
	after, e = r.rateHistory()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("body reclamation reset rate", after, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reclaimed rate recovery", e)
	}
	server, request, _ = anonymousHTTP(t, r, siteID(r.site.State()))
	defer server.Close()
	request("POST", "/test/bbs.cgi", post)
	_, body = request("POST", "/test/bbs.cgi", post)
	after, e = r.rateHistory()
	if e != nil || !strings.Contains(body, "ERROR:") || len(after) != 1 {
		t.Fatal("reclaimed body restart bypassed quota", after, e, body)
	}
}
