// 回収正本・証拠・固定ファイル集合の欠落/改変時に、未知の本体を消さず隔離する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"oimobbs/internal/postcapture"
)

func TestPublicBodyReclamationRejectsUnsafeRecovery(t *testing.T) {
	for _, kind := range []string{"unknown", "changed", "missing_ledger", "missing_evidence"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			cfg, repo := adminFixture(t)
			defer func() {
				if repo != nil {
					_ = repo.Close()
				}
			}()
			board, e := repo.CreateBoard(ctx, "body", "回収隔離")
			if e != nil {
				t.Fatal(e)
			}
			if e = repo.EnablePublicBodyReclamation(ctx); e != nil {
				t.Fatal(e)
			}
			form := formServer(t, repo, siteID(repo.site.State()), board.ID)
			created, e := sendForm(form, url.Values{"bbs": {"body"}, "subject": {"isolation"}, "MESSAGE": {"private-original"}, "oimo_request_id": {"body-fault-create-0001"}})
			form.Close()
			if e != nil || !created.Accepted {
				t.Fatal(created, e)
			}
			hideBodyFixture(t, repo, board.ID, created.Key)
			repo.posting[board.ID].deletionCheckpoint = func(s string) error {
				if s == "reclaim:proof" {
					return errors.New("crash")
				}
				return nil
			}
			if e = repo.ReclaimPublicBodies(ctx, 1); e == nil {
				t.Fatal("checkpoint ignored")
			}
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(cfg.DataDir, "boards", board.ID.String(), "threads", fmt.Sprint(created.Key))
			switch kind {
			case "unknown":
				e = os.WriteFile(filepath.Join(dir, "keep-unknown"), []byte("keep"), 0600)
			case "changed":
				e = os.WriteFile(filepath.Join(dir, "delta-000001.wal"), []byte("keep-changed"), 0600)
			case "missing_ledger":
				e = os.Rename(filepath.Join(cfg.DataDir, "expiry", board.ID.String(), fmt.Sprint(created.Key)), filepath.Join(t.TempDir(), "ledger"))
			case "missing_evidence":
				e = os.Rename(filepath.Join(cfg.DataDir, "evidence", board.ID.String()), filepath.Join(t.TempDir(), "private"))
			}
			if e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e == nil {
				t.Fatal("unsafe recovery accepted")
			}
			if _, e = os.Lstat(filepath.Join(dir, "current.json")); e != nil {
				t.Fatal("unsafe body removed", e)
			}
		})
	}
}
