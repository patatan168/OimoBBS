// 日別監査への引渡しを実fileで停止・再開し、監査の重複や本文混入を拒否する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestThreadAuditTransferRecovery(t *testing.T) {
	for _, stage := range []string{"", "audit:intent", "audit:entry", "audit:receipt", "audit:ledger"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			cfg, repo := adminFixture(t)
			defer func() {
				if repo != nil {
					_ = repo.Close()
				}
			}()
			board, e := repo.CreateBoard(ctx, "auditbody", "監査引渡し")
			if e != nil {
				t.Fatal(e)
			}
			if e = repo.EnablePublicBodyReclamation(ctx); e != nil {
				t.Fatal(e)
			}
			form := formServer(t, repo, siteID(repo.site.State()), board.ID)
			created, e := sendForm(form, url.Values{"bbs": {"auditbody"}, "subject": {"secret-thread-title"}, "MESSAGE": {"secret-post-body"}, "oimo_request_id": {"audit-transfer-create-0001"}})
			form.Close()
			if e != nil || !created.Accepted {
				t.Fatal(created, e)
			}
			hideBodyFixture(t, repo, board.ID, created.Key)
			if e = repo.ReclaimPublicBodies(ctx, 8); e != nil {
				t.Fatal(e)
			}
			b := repo.posting[board.ID]
			b.deletionCheckpoint = func(s string) error {
				if stage != "" && s == stage {
					return errors.New("crash")
				}
				return nil
			}
			e = repo.TransferThreadAudits(ctx, 8)
			if (e != nil) != (stage != "") {
				t.Fatal(e)
			}
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("audit restart", e)
			}
			if e = repo.TransferThreadAudits(ctx, 8); e != nil {
				t.Fatal("resume", e)
			}
			b = repo.posting[board.ID]
			state := b.deletions[created.Key].State()
			summaries, e := b.threads[created.Key].ThreadAudit(0)
			if e != nil || len(summaries) != 2 {
				t.Fatal("source audit", e)
			}
			unexpired, e := b.threads[created.Key].ThreadAudit(summaries[0].Committed)
			if e != nil || len(unexpired) != 1 || unexpired[0].ID != summaries[1].ID {
				t.Fatal("audit exact expiry boundary", e)
			}

			var transfer threadAuditTransfer
			if strictjson.Decode(state.Rows["reclamation:audit"].Value, &transfer) != nil || len(transfer.Days) != 1 || transfer.Days[0].Count != 2 {
				t.Fatal("audit completion shape", transfer)
			}
			proofs, e := b.bodyReclamations()
			if e != nil || transfer.verify(proofs[created.Key], b.key.Public().(ed25519.PublicKey)) != nil {
				t.Fatal("audit signature", e)
			}
			var deletion DeletionRecord
			if strictjson.Decode(state.Rows["deletion:"+transfer.Deletion.String()].Value, &deletion) != nil || deletion.Audit != "complete" {
				t.Fatal("audit ledger state")
			}
			before := state.Seq
			if e = repo.TransferThreadAudits(ctx, 8); e != nil || b.deletions[created.Key].State().Seq != before {
				t.Fatal("duplicate transfer", e)
			}
			// 一般の管理監査も新しいthread_summaryをcontrol要約と混同しない。
			if _, e = repo.EnableControlSnapshots(ctx); e != nil {
				t.Fatal("control audit with thread summary", e)
			}
			for _, day := range transfer.Days {
				raw, e := os.ReadFile(filepath.Join(cfg.DataDir, "audit", board.ID.String(), day.Day, "control-000001.wal"))
				if e != nil {
					t.Fatal(e)
				}
				for _, secret := range []string{"secret-thread-title", "secret-post-body", "127.0.0.1", "source_ip"} {
					if strings.Contains(string(raw), secret) {
						t.Fatal("private data in thread audit", secret)
					}
				}
			}
			if _, e = os.Lstat(filepath.Join(cfg.DataDir, "boards", board.ID.String(), "threads", fmt.Sprint(created.Key))); !os.IsNotExist(e) {
				t.Fatal("audit transfer recreated public body", e)
			}
			bad := transfer
			bad.Days = append([]threadAuditDay{}, transfer.Days...)
			bad.Days[0].Count++
			if e = bad.verify(proofs[created.Key], b.key.Public().(ed25519.PublicKey)); e == nil {
				t.Fatal("audit signature tamper accepted")
			}
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			source := filepath.Join(cfg.DataDir, "audit", board.ID.String(), transfer.Days[0].Day)
			if e = os.Rename(source, filepath.Join(t.TempDir(), "missing-audit")); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e == nil {
				t.Fatal("missing required day accepted")
			}
		})
	}
}
