// 同意前の保存禁止・秘密の非公開・再起動と同意期限後の再送を検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/url"
	"oimobbs/internal/abuse"
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
	for _, attempt := range []struct {
		f     url.Values
		token string
	}{{fields, first.Confirmation.Token + "x"}, {fields, ""}} {
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
	clockTime := time.Now()
	expiredToken, e := abuse.IssueConsent(abuse.Consent{Site: report.SiteID, Terms: 1, Text: repo.liveConsent.Load().Digest, Issued: clockTime.Unix() - 365*86400, Expires: clockTime.Unix()}, b.confirmKey[:], 5)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return clockTime }; return nil, nil }); e != nil {
		t.Fatal(e)
	}
	expired, e := sendFormOnce(server, fields, expiredToken)
	if e != nil || expired.Accepted || expired.Confirmation == nil {
		t.Fatal("expired confirmation bypassed by retry", expired, e)
	}
	// 新しい確認後も同じ明示要求IDなので、既存の一投稿へ戻る。
	again, e := sendFormOnce(server, fields, expired.Confirmation.Token)
	if e != nil || !again.Accepted || !again.Duplicate || again.Key != accepted.Key {
		t.Fatal(again, e)
	}
}
