// 確認前の保存禁止、内容/時刻/板への束縛、再起動後のCookie往復を実HTTPで検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyConfirmationBeforeCommit(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "確認試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, repo, report.SiteID, info.ID)
	defer func() { server.Close() }()
	fields := url.Values{"bbs": {"news"}, "subject": {"題"}, "FROM": {"名前#private-secret"}, "MESSAGE": {"確認本文"}, "oimo_request_id": {"confirmation-request-1"}}
	first, e := sendFormOnce(server, fields, "")
	if e != nil || first.Accepted || first.Confirmation == nil {
		t.Fatal(first, e)
	}
	if first.Confirmation.Preview.Name != "名前" || first.Confirmation.Preview.Trip == "" || first.Confirmation.Preview.Body != "確認本文" {
		t.Fatal("wrong preview")
	}
	preview, _ := json.Marshal(first.Confirmation)
	if strings.Contains(string(preview), "private-secret") || strings.Contains(string(preview), first.Confirmation.Token) {
		t.Fatal("secret in confirmation preview")
	}
	b := repo.posting[info.ID]
	before := b.control.State().Seq
	if len(b.threads) != 0 || len(b.journals) != 0 {
		t.Fatal("confirmation persisted a post")
	}
	changed := url.Values{"bbs": {"news"}, "subject": {"題"}, "FROM": {"名前#private-secret"}, "MESSAGE": {"変更本文"}}
	for _, attempt := range []struct {
		f     url.Values
		token string
	}{{changed, first.Confirmation.Token}, {fields, first.Confirmation.Token + "x"}, {fields, ""}} {
		r, e := sendFormOnce(server, attempt.f, attempt.token)
		if e != nil || r.Accepted || r.Confirmation == nil {
			t.Fatal("unconfirmed accepted", r, e)
		}
	}
	if b.control.State().Seq != before || len(b.journals) != 0 {
		t.Fatal("confirmation consumed reservation")
	}
	// 未受理の確認トークンも、永続鍵を読み直した後に検証できる。
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	server = formServer(t, repo, report.SiteID, info.ID)
	accepted, e := sendFormOnce(server, fields, first.Confirmation.Token)
	if e != nil || !accepted.Accepted || accepted.Number != 1 {
		t.Fatal(accepted, e)
	}
	if e = filepath.WalkDir(cfg.DataDir, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if entry.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if strings.Contains(string(raw), first.Confirmation.Token) {
			t.Fatalf("confirmation secret persisted in %s", path)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	retry, e := sendFormOnce(server, fields, first.Confirmation.Token)
	if e != nil || !retry.Accepted || !retry.Duplicate || retry.Key != accepted.Key {
		t.Fatal(retry, e)
	}
	b = repo.posting[info.ID]
	clockTime := time.Unix(first.Confirmation.Expires, 0)
	if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return clockTime }; return nil, nil }); e != nil {
		t.Fatal(e)
	}
	expired, e := sendFormOnce(server, fields, first.Confirmation.Token)
	if e != nil || expired.Accepted || expired.Confirmation == nil {
		t.Fatal("expired confirmation bypassed by retry", expired, e)
	}
	// 新しい確認後も同じ明示要求IDなので、既存の一投稿へ戻る。
	again, e := sendFormOnce(server, fields, expired.Confirmation.Token)
	if e != nil || !again.Accepted || !again.Duplicate || again.Key != accepted.Key {
		t.Fatal(again, e)
	}
}

// 公開条件や規約の変更では、本文が同じでも古い署名を受理しない。
func TestConfirmationPolicyBinding(t *testing.T) {
	key := domain.Hash{5}
	now := time.Unix(1800000000, 0)
	settings := defaultBoardSettings()
	policy := domain.Policy{Version: 1, IDMode: "required", SlipMode: "none", UserPostLimit: 1000, DATUserLimit: 524288, Commands: []string{}}
	versions := domain.Versions{Site: 1, Board: 1, Thread: 1}
	digest, e := confirmationPolicy(key, versions, policy, settings.Input)
	if e != nil {
		t.Fatal(e)
	}
	want := abuse.Confirmation{Board: domain.ID{1}, Terms: 1, Request: domain.Hash{2}, Policy: digest, Issued: now.Unix(), Expires: now.Unix() + 600}
	token, e := abuse.IssueConfirmation(want, key[:], 5)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name   string
		modify func(*domain.Versions, *domain.Policy, *boardInput)
	}{
		{"site_version", func(v *domain.Versions, p *domain.Policy, i *boardInput) { v.Site++ }},
		{"board_version", func(v *domain.Versions, p *domain.Policy, i *boardInput) { v.Board++ }},
		{"thread_version", func(v *domain.Versions, p *domain.Policy, i *boardInput) { v.Thread++ }},
		{"public_ip", func(v *domain.Versions, p *domain.Policy, i *boardInput) { p.RequirePublicIP = true }},
		{"id", func(v *domain.Versions, p *domain.Policy, i *boardInput) { p.IDMode = "optional" }},
		{"name", func(v *domain.Versions, p *domain.Policy, i *boardInput) { i.ForceNoname = true }},
		{"mail", func(v *domain.Versions, p *domain.Policy, i *boardInput) { i.HideMail = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, p, i := versions, policy, settings.Input
			tc.modify(&v, &p, &i)
			changed, e := confirmationPolicy(key, v, p, i)
			if e != nil {
				t.Fatal(e)
			}
			w := want
			w.Policy = changed
			if abuse.VerifyConfirmation(token, w, key[:], 5, now) == nil {
				t.Fatal("changed policy accepted")
			}
		})
	}
	for _, modify := range []func(*abuse.Confirmation){func(c *abuse.Confirmation) { c.Terms++ }, func(c *abuse.Confirmation) { c.Board = domain.ID{3} }, func(c *abuse.Confirmation) { c.Request = domain.Hash{4} }} {
		w := want
		modify(&w)
		if abuse.VerifyConfirmation(token, w, key[:], 5, now) == nil {
			t.Fatal("changed binding accepted")
		}
	}
}
