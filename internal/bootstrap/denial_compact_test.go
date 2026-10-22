// 空白変更の同文を既存regexpへ変換し、投稿・再送・復旧へ接続できることを検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/postinput"
)

func TestCompactBodyCondition(t *testing.T) {
	input := AdminRuleInput{Target: "a.b広告", Operations: []string{"create"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"body", "compact_exact", "deny"}}
	if err := input.validate(); err != nil {
		t.Fatal(err)
	}
	c := input.conditions()[0]
	if c.Operator != "regexp" {
		t.Fatal(c)
	}
	_, re, err := compileDenialCondition(c)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"a.b広告", " \ta . b\n広　告\u0085", "a\v.\u2028b広告"} {
		if !re.MatchString(value) {
			t.Fatal("miss", value)
		}
	}
	for _, value := range []string{"axb広告", "A.b広告", "a.b廣告", "前a.b広告", "a.b広告後"} {
		if re.MatchString(value) {
			t.Fatal("false positive", value)
		}
	}
	for _, value := range []string{"", " \n　", string([]byte{0xff}), strings.Repeat("a", 1025)} {
		input.Target = value
		if input.validate() == nil {
			t.Fatal("bad target accepted")
		}
	}
	input.Target = "spam"
	input.Match.Field = "name"
	if input.validate() == nil {
		t.Fatal("non-body compact matching accepted")
	}
}

func TestCompactBodyRuleHTTPAndRestart(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "compact", "定型文")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	res, _ := c.rules(board.ID)
	path := fmt.Sprintf("/api/v1/boards/%s/rules", board.ID)
	input := AdminRuleInput{Target: "広告", Operations: []string{"create"}, Minutes: 60, Reason: "spam", Match: &AdminRuleMatch{"body", "compact_exact", "deny"}}
	raw, _ := json.Marshal(input)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"compact-rule-request-0001"}}
	for range 2 {
		res, body := c.request("POST", path, string(raw), headers)
		if res.StatusCode != 200 || !strings.Contains(body, `"operator":"regexp"`) {
			t.Fatal(res.StatusCode, body)
		}
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	result, err := sendForm(form, url.Values{"bbs": {"compact"}, "subject": {"通常"}, "MESSAGE": {"通常の本文"}, "oimo_request_id": {"compact-create-valid-01"}})
	if err != nil || !result.Accepted {
		t.Fatal(result, err)
	}
	denied, err := sendForm(form, url.Values{"bbs": {"compact"}, "subject": {"拒否"}, "MESSAGE": {"広　告"}, "oimo_request_id": {"compact-create-denied-01"}})
	if err != nil || denied.Accepted {
		t.Fatal(denied, err)
	}
	form.Close()
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[board.ID]
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		denied, _, err := b.matchingRules(netip.MustParseAddr("127.0.0.1"), postinput.Input{Body: "広\n告"}, domain.Hash{}, true, domain.Time(b.clock().UnixNano()))
		if err == nil && !denied {
			t.Error("restarted rule missed body")
		}
		return nil, err
	})
	if err != nil {
		t.Fatal(err)
	}
}
