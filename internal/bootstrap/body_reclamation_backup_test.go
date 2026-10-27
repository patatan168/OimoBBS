// 公開本体のないbackupでも回収正本と受理証拠を照合し、再公開可能とは表示しない。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func TestReclaimedBodyBackupReplay(t *testing.T) {
	ctx := context.Background()
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			_ = repo.Close()
		}
	}()
	board, e := repo.CreateBoard(ctx, "body", "回収候補")
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.EnablePublicBodyReclamation(ctx); e != nil {
		t.Fatal(e)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	created, e := sendForm(form, url.Values{"bbs": {"body"}, "subject": {"backup"}, "MESSAGE": {"private-original"}, "oimo_request_id": {"body-backup-create-0001"}})
	form.Close()
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	hideBodyFixture(t, repo, board.ID, created.Key)
	if e = repo.ReclaimPublicBodies(ctx, 8); e != nil {
		t.Fatal(e)
	}
	if e = repo.TransferThreadAudits(ctx, 8); e != nil {
		t.Fatal("thread audit transfer", e)
	}

	b := repo.posting[board.ID]
	if _, e = b.worker.Submit(ctx, func() (any, error) { return b.threads[created.Key].MaintainPack(ctx, b.clock, true) }); e != nil {
		t.Fatal("reclaimed pack maintenance", e)
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	online := filepath.Join(parent, "online")
	cut, e := repo.CopyBoardBackup(ctx, board.ID, online, OnlineBackupGroupOptions{})
	if e != nil {
		t.Fatal("online copy", e)
	}
	for _, v := range cut.Captures {
		if v.Kind == "thread" {
			t.Fatal("reclaimed thread copied", v)
		}
	}
	// 改変済み証明を正本へ保存する前の署名検査。
	proofs, e := repo.posting[board.ID].bodyReclamations()
	if e != nil {
		t.Fatal(e)
	}
	proof := proofs[created.Key]
	state := repo.posting[board.ID].deletions[created.Key].State()
	rows := map[string]store.ControlRow{}
	for name, row := range state.Rows {
		if name != "reclamation:carry" {
			rows[name] = row
		}
	}
	if _, err := readBodyReclamation(store.ControlState{Seq: state.Seq, Rows: rows}, board.ID, created.Key, repo.posting[board.ID].key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("completed carry without seal accepted")
	}
	checkBodyReclamationFixture(t, proof, repo.posting[board.ID].key.Public().(ed25519.PublicKey))
	proof.RecordsSHA = domain.Hash{1}
	if e = proof.Verify(repo.posting[board.ID].key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("proof tamper accepted")
	}
	admin := newAdminClient(t, repo)
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, page := admin.request("GET", fmt.Sprintf("/boards/%s/threads/%d/moderation", board.ID, created.Key), "", nil)
	admin.server.Close()
	if res.StatusCode != 200 || !strings.Contains(page, "<dt>公開用保存データ</dt><dd>回収済み</dd>") || !strings.Contains(page, "<dt>保存掃除</dt><dd>未完了</dd>") {
		t.Fatal("cleanup scope display", res.StatusCode, page)
	}
	for range 2 {
		if _, e = repo.EnableControlSnapshots(ctx); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "body-control")
	if _, e = repo.PrepareControlSnapshot(ctx, candidate, 6); e != nil {
		t.Fatal("reclaimed control snapshot", e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(ctx, cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal("activate reclaimed snapshot", e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reclaimed snapshot recovery", e)
	}
	if !repo.posting[board.ID].threads[created.Key].Reclaimed() {
		t.Fatal("snapshot revived reclaimed body")
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	body, keys, work := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if _, e = CaptureOfflineBackup(ctx, cfg, body); e != nil {
		t.Fatal("offline capture", e)
	}
	if _, e = ExportBackupKeys(ctx, cfg, body, keys); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	report, e := VerifyBackupReplay(ctx, body, keys, work)
	if e != nil || !report.Replayed || report.RestoreReady {
		t.Fatal("reclaimed replay", report, e)
	}
}
