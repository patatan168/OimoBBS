// 旧部分backupの本文と最新台帳を合成し、削除・規制・期限を巻き戻さないことを検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oimobbs/internal/app"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func restoreTarget(t *testing.T, cfg Config) Config {
	t.Helper()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg.DataDir = filepath.Join(parent, "restored")
	return cfg
}

// TestPublicRestoreOldBackupLatestLedger は旧本文を補って最新のhide/redactを適用する。
func TestPublicRestoreOldBackupLatestLedger(t *testing.T) {
	for _, kind := range []string{"none", "hide", "redact", "reply", "pack"} {
		t.Run(kind, func(t *testing.T) {
			cfg, backup := backupFixture(t)
			if _, e := CaptureOfflineBackup(t.Context(), cfg, backup); e != nil {
				t.Fatal(e)
			}
			repo, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			boards, e := repo.Boards()
			if e != nil || len(boards) != 1 {
				t.Fatal(boards, e)
			}
			board := boards[0]
			b := repo.posting[board.ID]
			var key uint64
			for k := range b.threads {
				key = k
			}
			admin := newAdminClient(t, repo)
			if admin.login(adminTestSecret) != 303 {
				t.Fatal("login")
			}
			if kind == "reply" {
				form := formServer(t, repo, siteID(repo.site.State()), board.ID)
				accepted, e := sendForm(form, url.Values{"bbs": {"backup"}, "key": {fmt.Sprint(key)}, "MESSAGE": {"latest-reply"}, "oimo_request_id": {"latest-restore-reply-0001"}})
				form.Close()
				if e != nil || !accepted.Accepted {
					t.Fatal(accepted, e)
				}
			}
			if kind == "hide" || kind == "redact" {
				path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, key)
				res, _ := admin.request("GET", path, "", nil)
				edit := AdminModeration{Kind: kind, Ranges: []app.RedactionRange{}}
				if kind == "redact" {
					edit.Ranges = []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}
				}
				raw, _ := json.Marshal(edit)
				res, body := admin.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"old-backup-moderation-0001"}})
				if res.StatusCode != 200 {
					t.Fatal(res.StatusCode, body)
				}
			}
			res, settings := admin.board(board.ID.String())
			edit := settings.Settings
			edit.Reply = "disabled"
			rawPolicy, _ := json.Marshal(edit)
			res, body := admin.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(rawPolicy), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"latest-restore-policy-0001"}})
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			admin.server.Close()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			thread := filepath.Join(cfg.DataDir, "boards", board.ID.String(), "threads", fmt.Sprint(key))
			raw, e := readPrivate(filepath.Join(thread, "current.json"), 16<<10)
			if e != nil {
				t.Fatal(e)
			}
			current, e := store.DecodeCurrent(raw)
			if e != nil {
				t.Fatal(e)
			}
			missingFile := current.Delta.File
			if kind == "pack" {
				missingFile = current.Base.File
			}
			if e = os.Remove(filepath.Join(thread, missingFile)); e != nil {
				t.Fatal(e)
			}
			target := restoreTarget(t, cfg)
			if _, e = RestorePublicRepository(t.Context(), cfg, target); e == nil {
				t.Fatal("missing body accepted without backup")
			}
			report, e := RestorePublicRepositoryFromBackup(t.Context(), cfg, target, backup)
			if e != nil || !report.RestoreReady || report.Backup == nil || report.PayloadFilesRecovered != 1 {
				t.Fatal(report, e)
			}
			restored, e := OpenPostingRepository(target, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer restored.Close()
			checkAdmin := newAdminClient(t, restored)
			if checkAdmin.login(adminTestSecret) != 303 {
				t.Fatal("restored admin login")
			}
			_, settings = checkAdmin.board(board.ID.String())
			checkAdmin.server.Close()
			if settings.Settings.Reply != "disabled" {
				t.Fatal("latest posting policy rolled back")
			}

			snap, e := restored.Thread(t.Context(), board.ID, key)
			if e != nil {
				t.Fatal(e)
			}
			if kind == "hide" {
				if snap != nil {
					t.Fatal("hidden thread resurrected")
				}
			} else {
				if snap == nil {
					t.Fatal("thread missing")
				}
				text := string(snap.DAT)
				if kind == "redact" && strings.Contains(text, "first") {
					t.Fatal("redacted body resurrected", text)
				}
				if kind == "reply" && !strings.Contains(text, "latest-reply") {
					t.Fatal("latest accepted frame lost", text)
				}
				if !strings.Contains(text, "second") {
					t.Fatal("unrelated reply lost", text)
				}
			}
			if _, e = os.Stat(filepath.Join(thread, missingFile)); !os.IsNotExist(e) {
				t.Fatal("source modified", e)
			}
		})
	}
}

// TestPublicRestoreBackupRejectsMissingSafetyState は私有正本/台帳/currentを旧backupで補わない。
func TestPublicRestoreBackupRejectsMissingSafetyState(t *testing.T) {
	for _, missing := range []string{"evidence", "expiry", "current", "candidate", "cancel"} {
		t.Run(missing, func(t *testing.T) {
			cfg, repo, c, board, key := reportTestSetup(t)
			c.server.Close()
			if e := repo.Close(); e != nil {
				t.Fatal(e)
			}
			parent := t.TempDir()
			os.Chmod(parent, 0700)
			backup := filepath.Join(parent, "backup")
			if _, e := CaptureOfflineBackup(t.Context(), cfg, backup); e != nil {
				t.Fatal(e)
			}
			repo, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			admin := newAdminClient(t, repo)
			admin.login(adminTestSecret)
			path := "/api/v1/boards/" + board.String() + "/threads/" + key + "/moderation"
			res, _ := admin.request("GET", path, "", nil)
			res, body := admin.request("POST", path, `{"kind":"hide","ranges":[],"hide_title":false}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"missing-ledger-hide-0001"}})
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			admin.server.Close()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			thread := filepath.Join(cfg.DataDir, "boards", board.String(), "threads", key)
			raw, e := readPrivate(filepath.Join(thread, "current.json"), 16<<10)
			if e != nil {
				t.Fatal(e)
			}
			current, e := store.DecodeCurrent(raw)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.Remove(filepath.Join(thread, current.Delta.File)); e != nil {
				t.Fatal(e)
			}
			ctx := t.Context()
			switch missing {
			case "evidence":
				e = os.RemoveAll(filepath.Join(cfg.DataDir, "evidence", board.String()))
			case "expiry":
				e = os.RemoveAll(filepath.Join(cfg.DataDir, "expiry", board.String()))
			case "current":
				e = os.Remove(filepath.Join(thread, "current.json"))
			case "candidate":
				e = os.WriteFile(filepath.Join(backup, "manifest.json"), []byte("{}"), 0600)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if e != nil {
				t.Fatal(e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			target := restoreTarget(t, cfg)
			report, e := RestorePublicRepositoryFromBackup(ctx, cfg, target, backup)
			if e == nil || report.RestoreReady {
				t.Fatal("unsafe restore accepted", report, e)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
			if _, e = os.Stat(target.DataDir); !os.IsNotExist(e) {
				t.Fatal("failed destination published", e)
			}
			names, e := os.ReadDir(filepath.Dir(target.DataDir))
			if e != nil {
				t.Fatal(e)
			}
			for _, name := range names {
				if strings.HasPrefix(name.Name(), ".public-restore-") {
					t.Fatal("work left after failure")
				}
			}
		})
	}
}

// TestPublicRestoreBackupRejectsUnknownGeneration は旧世代を最新currentへ置換しない。
func TestPublicRestoreBackupRejectsUnknownGeneration(t *testing.T) {
	cfg, backup := backupFixture(t)
	if _, e := CaptureOfflineBackup(t.Context(), cfg, backup); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	boards, e := repo.Boards()
	if e != nil {
		t.Fatal(e)
	}
	board := boards[0]
	var key uint64
	for k := range repo.posting[board.ID].threads {
		key = k
	}
	if _, e = repo.CompactThread(t.Context(), board.ID, key, 6, true); e != nil {
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	thread := filepath.Join(cfg.DataDir, "boards", board.ID.String(), "threads", fmt.Sprint(key))
	raw, e := readPrivate(filepath.Join(thread, "current.json"), 16<<10)
	if e != nil {
		t.Fatal(e)
	}
	current, e := store.DecodeCurrent(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(thread, current.Base.File)); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	target := restoreTarget(t, cfg)
	report, e := RestorePublicRepositoryFromBackup(t.Context(), cfg, target, backup)
	if e == nil || report.RestoreReady {
		t.Fatal("old generation substituted", report, e)
	}
	assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
	if _, e = os.Stat(target.DataDir); !os.IsNotExist(e) {
		t.Fatal("unsafe destination published", e)
	}
}

// TestPublicRestoreBackupPreservesLatestReports は旧候補にない依頼を最新側から保持する。
func TestPublicRestoreBackupPreservesLatestReports(t *testing.T) {
	cfg, repo, c, board, key := reportTestSetup(t)
	c.server.Close()
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	os.Chmod(parent, 0700)
	backup := filepath.Join(parent, "old-backup")
	if _, e := CaptureOfflineBackup(t.Context(), cfg, backup); e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	c = newReportTestClient(t, repo)
	id, secret := createTestReport(t, c, key)
	c.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	thread := filepath.Join(cfg.DataDir, "boards", board.String(), "threads", key)
	raw, e := readPrivate(filepath.Join(thread, "current.json"), 16<<10)
	if e != nil {
		t.Fatal(e)
	}
	current, e := store.DecodeCurrent(raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(filepath.Join(thread, current.Delta.File)); e != nil {
		t.Fatal(e)
	}
	target := restoreTarget(t, cfg)
	report, e := RestorePublicRepositoryFromBackup(t.Context(), cfg, target, backup)
	if e != nil || !report.RestoreReady {
		t.Fatal(report, e)
	}
	restored, e := OpenPostingRepository(target, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	signing, e := reportKey(target.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	saved, e := readReport(target.DataDir, id, signing)
	if e != nil || !reportSecretMatches(saved, secret) {
		t.Fatal("latest report lost", saved, e)
	}
}
