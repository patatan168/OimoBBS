// 実投稿・圧縮世代の停止中捕捉、改変拒否、期限、回収の中断再開を検証する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func backupFixture(t *testing.T) (Config, string) {
	t.Helper()
	cfg, r := adminFixture(t)
	defer r.Close()
	board, e := r.CreateBoard(context.Background(), "backup", "バックアップ")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), board.ID)
	defer server.Close()
	first, e := sendForm(server, url.Values{"bbs": {"backup"}, "subject": {"保存試験"}, "MESSAGE": {"first"}, "oimo_request_id": {"backup-create-0001"}})
	if e != nil || first.Key == 0 {
		t.Fatal(first)
	}
	if _, e = r.EnablePostingPacks(context.Background()); e != nil {
		t.Fatal(e)
	}
	if _, e = r.CompactThread(context.Background(), board.ID, first.Key, 6, true); e != nil {
		t.Fatal(e)
	}
	reply, e := sendForm(server, url.Values{"bbs": {"backup"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"second"}, "oimo_request_id": {"backup-reply-0001"}})
	if e != nil || reply.Number != 2 {
		t.Fatal(reply)
	}
	server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	return cfg, filepath.Join(parent, "backup-copy")
}

func TestOfflineBackupRoundTrip(t *testing.T) {
	cfg, out := backupFixture(t)
	report, e := CaptureOfflineBackup(context.Background(), cfg, out)
	if e != nil || !report.Verified || report.RestoreReady || report.Files < 10 {
		t.Fatal(report, e)
	}
	if _, e = CaptureOfflineBackup(context.Background(), cfg, out); e == nil {
		t.Fatal("existing output reused")
	}
	verified, e := VerifyOfflineBackup(context.Background(), cfg, out)
	if e != nil || !verified.Verified || verified.ID != report.ID || verified.Bytes != report.Bytes {
		t.Fatal(verified, e)
	}
	if e = filepath.WalkDir(out, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if strings.HasSuffix(path, ".key") || strings.HasSuffix(path, ".seed") || strings.HasSuffix(path, "emergency.reserve") {
			t.Fatal("secret or reserve copied", path)
		}
		if !d.IsDir() && d.Name() == "delta-000001.wal" {
			t.Fatal("old thread generation copied", path)
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	// 捕捉後に正本へ新しい板を追加しても、コピーの認証境界は変わらない。
	r, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ManageEmergencyReserve(cfg, "status", 0, false); e == nil {
		t.Fatal("offline exclusion absent")
	}
	if _, e = r.CreateBoard(context.Background(), "later", "後から追加"); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyOfflineBackup(context.Background(), cfg, out); e != nil {
		t.Fatal(e)
	}
	if _, e = verifyOfflineBackup(context.Background(), cfg, out, func() time.Time { return time.Unix(0, int64(report.Expires)) }); e == nil {
		t.Fatal("expired backup verified")
	}
}

func TestOfflineBackupTamper(t *testing.T) {
	for _, kind := range []string{"manifest", "rehash", "payload", "missing", "extra", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			cfg, out := backupFixture(t)
			if _, e := CaptureOfflineBackup(context.Background(), cfg, out); e != nil {
				t.Fatal(e)
			}
			metadata := filepath.Join(out, "owners", "metadata")
			var target string
			if e := filepath.WalkDir(metadata, func(path string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if !d.IsDir() && target == "" {
					target = path
				}
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			switch kind {
			case "manifest":
				if e := os.WriteFile(filepath.Join(out, "manifest.json"), []byte("{}"), 0600); e != nil {
					t.Fatal(e)
				}
			case "rehash":
				raw, e := os.ReadFile(filepath.Join(out, "manifest.json"))
				if e != nil {
					t.Fatal(e)
				}
				var envelope backupEnvelope
				if e = json.Unmarshal(raw, &envelope); e != nil {
					t.Fatal(e)
				}
				var m backupManifest
				if e = json.Unmarshal(envelope.Manifest, &m); e != nil {
					t.Fatal(e)
				}
				m.ID = domain.NewID()
				envelope.Manifest, e = json.Marshal(m)
				if e != nil {
					t.Fatal(e)
				}
				envelope.SHA = sha256.Sum256(envelope.Manifest)
				changed, e := json.Marshal(envelope)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(out, "manifest.json"), changed, 0600); e != nil {
					t.Fatal(e)
				}
			case "payload":
				if e := os.WriteFile(target, []byte("changed"), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing":
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				}
			case "extra":
				if e := os.WriteFile(filepath.Join(out, "extra"), nil, 0600); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink(filepath.Join(cfg.DataDir, "instance.json"), target); e != nil {
					t.Fatal(e)
				}
			case "hardlink":
				if e := os.Link(target, filepath.Join(filepath.Dir(out), "alias")); e != nil {
					t.Fatal(e)
				}
			}
			if _, e := VerifyOfflineBackup(context.Background(), cfg, out); e == nil {
				t.Fatal("unsafe backup accepted", kind)
			}
		})
	}
}

func TestOfflineBackupExpiryAndInterruptedReclamation(t *testing.T) {
	cfg, out := backupFixture(t)
	result, e := CaptureOfflineBackup(context.Background(), cfg, out)
	if e != nil {
		t.Fatal(e)
	}
	live, e := ReclaimOfflineBackup(context.Background(), cfg, out, true)
	if e != nil || live.Expired || live.Applied {
		t.Fatal(live, e)
	}
	clock := func() time.Time { return time.Unix(0, int64(result.Expires)) }
	preview, e := reclaimOfflineBackup(context.Background(), cfg, out, false, clock, func(string) error { return nil })
	if e != nil || !preview.Expired || preview.Applied {
		t.Fatal(preview, e)
	}
	crash := errors.New("interrupted after unlink")
	_, e = reclaimOfflineBackup(context.Background(), cfg, out, true, clock, func(string) error { return crash })
	if !errors.Is(e, crash) {
		t.Fatal(e)
	}
	if _, e = VerifyOfflineBackup(context.Background(), cfg, out); e == nil {
		t.Fatal("incomplete reclamation reported complete")
	}
	done, e := reclaimOfflineBackup(context.Background(), cfg, out, true, clock, func(string) error { return nil })
	if e != nil || !done.Applied {
		t.Fatal(done, e)
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("copy remains", e)
	}
	r, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("source damaged", e)
	}
	r.Close()
}

func TestOfflineBackupInterruptedCapture(t *testing.T) {
	cfg, out := backupFixture(t)
	now := time.Now()
	ctx, cancel := context.WithCancel(context.Background())
	_, e := captureOfflineBackup(ctx, cfg, out, func() time.Time { return now }, func(stage string) {
		if stage == "backup:file" {
			cancel()
		}
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(out, "manifest.json")); !os.IsNotExist(e) {
		t.Fatal("completed partial capture", e)
	}
	if _, e = VerifyOfflineBackup(context.Background(), cfg, out); e == nil {
		t.Fatal("partial capture verified")
	}
	if _, e = ReclaimOfflineBackup(context.Background(), cfg, out, true); e == nil {
		t.Fatal("unproved partial copy reclaimed")
	}
	// 確保済みの入力は読み込めるまま維持する。
	if _, e = store.HashBackupFile(context.Background(), filepath.Join(cfg.DataDir, "instance.json")); e != nil {
		t.Fatal(e)
	}
}

func TestOfflineBackupManifestValidation(t *testing.T) {
	for _, name := range []string{"../x", "/x", "a//b", "a/../b", "a\\b", "a:b", "a/./b"} {
		if safeBackupName(name) {
			t.Fatal(name)
		}
	}
	cfg, out := backupFixture(t)
	result, e := CaptureOfflineBackup(context.Background(), cfg, out)
	if e != nil {
		t.Fatal(e)
	}
	r, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	m, _, e := r.loadBackup(out)
	r.Close()
	if e != nil {
		t.Fatal(e)
	}
	m.Entries[0].Sequence++
	if _, e = validateBackupManifest(m); e == nil {
		t.Fatal("control sequence mismatch accepted")
	}
	if result.ID == (domain.ID{}) {
		t.Fatal("missing ID")
	}
}

func TestOfflineBackupExpiredSourceAndCaptureDeadline(t *testing.T) {
	cfg, out := backupFixture(t)
	future := func() time.Time { return time.Now().AddDate(0, 8, 0) }
	if _, e := captureOfflineBackup(context.Background(), cfg, out, future, func(string) {}); e == nil {
		t.Fatal("expired source backed up")
	}
	if _, e := os.Stat(out); !os.IsNotExist(e) {
		t.Fatal("created output for expired source", e)
	}
	now := time.Now()
	clock := func() time.Time { return now }
	_, e := captureOfflineBackup(context.Background(), cfg, out, clock, func(stage string) {
		if stage == "backup:manifest_synced" {
			now = now.Add(25 * time.Hour)
		}
	})
	if e == nil {
		t.Fatal("expired capture completed")
	}
	if _, e = os.Stat(filepath.Join(out, "manifest.json")); !os.IsNotExist(e) {
		t.Fatal("completion marker exists", e)
	}
	if _, e = os.Stat(filepath.Join(out, "manifest.pending")); e != nil {
		t.Fatal("failure artifacts were not preserved", e)
	}
}

func TestOfflineBackupJobRetention(t *testing.T) {
	cfg, base := backupFixture(t)
	for _, step := range []struct {
		label  string
		offset time.Duration
		job    bool
	}{{"near", 30*24*time.Hour - 30*time.Minute, true}, {"expired", 31 * 24 * time.Hour, false}} {
		out := base + "-" + step.label
		now := time.Now().Add(step.offset)
		report, e := captureOfflineBackup(context.Background(), cfg, out, func() time.Time { return now }, func(string) {})
		if e != nil {
			t.Fatal(e)
		}
		if step.job && int64(report.Expires) > now.Add(time.Hour).UnixNano() {
			t.Fatal("job expiry extended", report)
		}
		r, e := OpenPostingRepository(cfg, postcapture.Validate)
		if e != nil {
			t.Fatal(e)
		}
		m, _, e := r.loadBackup(out)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		hasJob := false
		for _, entry := range m.Entries {
			if entry.Kind == "job" {
				hasJob = true
			}
		}
		if hasJob != step.job {
			t.Fatal("expired job copied", hasJob, step.job)
		}
	}
}

func TestOfflineBackupRejectsPendingSourceWithoutRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	r.checkpoint = func(stage string) {
		if stage == "provisioning" {
			panic("stop at provisioning")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("missing interruption")
			}
		}()
		_, _ = r.CreateBoard(context.Background(), "pending", "未完成")
	}()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	hashSource := func() map[string]domain.Hash {
		result := map[string]domain.Hash{}
		e := filepath.WalkDir(cfg.DataDir, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				return nil
			}
			file, e := store.HashBackupFile(context.Background(), path)
			if e != nil {
				return e
			}
			result[path] = file.SHA
			return nil
		})
		if e != nil {
			t.Fatal(e)
		}
		return result
	}
	before := hashSource()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := CaptureOfflineBackup(context.Background(), cfg, filepath.Join(parent, "copy")); e == nil {
		t.Fatal("pending source captured")
	}
	if !reflect.DeepEqual(before, hashSource()) {
		t.Fatal("backup resumed or changed pending source")
	}
	// 通常のRepository復旧なら同じ正本の既知intentを再開できる。
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Close()
}
