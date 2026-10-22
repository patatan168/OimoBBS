// 正本設定のないCLIで部分的な再生作業領域をpreview/applyし、入力拒否を確認する。
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
)

// watchReportWriter は最初の報告を保存した後に、出力失敗で定期プロセスを停止させる。
type watchReportWriter struct {
	bytes.Buffer
	err error
}

func (w *watchReportWriter) Write(p []byte) (int, error) { _, _ = w.Buffer.Write(p); return 0, w.err }

// cliReplayCleanupFixture はfixture所有の鍵で、途中複写を表す認証済み計画を構成する。
func cliReplayCleanupFixture(t *testing.T, backup, keys, parent string) string {
	t.Helper()
	root := filepath.Join(parent, ".backup-replay-cli")
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(root, "keys"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, ".lock"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	master, e := os.ReadFile(filepath.Join(keys, "keys/master-000001.key"))
	if e != nil {
		t.Fatal(e)
	}
	defer clear(master)
	if e = os.WriteFile(filepath.Join(root, "keys/master-000001.key"), master, 0600); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(filepath.Join(backup, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var env struct {
		Manifest json.RawMessage `json:"manifest"`
	}
	if e = json.Unmarshal(raw, &env); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(root)
	if e != nil {
		t.Fatal(e)
	}
	st := info.Sys().(*syscall.Stat_t)
	now := time.Now()
	plan := map[string]any{"schema": 1, "mode": "verification_only", "root": root, "device": domain.U64(st.Dev), "inode": domain.U64(st.Ino), "created_at_ns": domain.Time(now.UnixNano()), "backup_manifest_sha256": domain.Hash(sha256.Sum256(raw)), "backup": env.Manifest, "journal_days": []string{now.UTC().Format("20060102"), now.UTC().AddDate(0, 0, 1).Format("20060102")}}
	payload, e := json.Marshal(plan)
	if e != nil {
		t.Fatal(e)
	}
	key, e := identity.DeriveKey(master, "backup_replay_cleanup", 1)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	envelope := map[string]any{"manifest": json.RawMessage(payload), "manifest_sha256": domain.Hash(sha256.Sum256(payload)), "manifest_mac": identity.MAC(key[:], "oimo/backup-replay-cleanup/v1", payload)}
	raw, e = json.Marshal(envelope)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "backup-replay.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	return root
}
func TestBackupReplayCleanupCLI(t *testing.T) {
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(parent, "data"), Public: bootstrap.PublicConfig{Listen: "127.0.0.1:8080", BaseURL: "http://127.0.0.1:8080"}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:8081", Origin: "http://127.0.0.1:8081", Transport: "loopback_tunnel"}, TrustedProxies: []string{}, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "replay cleanup"); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(cfg)
	if e != nil {
		t.Fatal(e)
	}
	config := filepath.Join(parent, "config.json")
	if e = os.WriteFile(config, raw, 0600); e != nil {
		t.Fatal(e)
	}
	backup, keys := filepath.Join(parent, "copy"), filepath.Join(parent, "separate-keys")
	for _, args := range [][]string{{"backup", "capture", "--config", config, "--output", backup}, {"backup", "export-keys", "--config", config, "--input", backup, "--output", keys}} {
		var out, diag bytes.Buffer
		if e := run(args, &out, &diag); e != nil {
			t.Fatal(e)
		}
	}
	work := filepath.Join(parent, "work")
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	root := cliReplayCleanupFixture(t, backup, keys, work)
	if e = os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(config); e != nil {
		t.Fatal(e)
	}
	stop := errors.New("watch output stopped")
	watchOut := &watchReportWriter{err: stop}
	var watchDiag bytes.Buffer
	if e = run([]string{"backup", "watch-replay", "--work-parent", work, "--keys", keys}, watchOut, &watchDiag); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	var watch bootstrap.ReplayMaintenanceReport
	if e = json.Unmarshal(watchOut.Bytes(), &watch); e != nil || watch.Apply || watch.Pass != 1 || watch.Status != "completed" || watch.Sweep.Items[0].Status != "verified" {
		t.Fatal(watch, e)
	}
	var sweepOut, sweepDiag bytes.Buffer
	if e = run([]string{"backup", "sweep-replay", "--work-parent", work, "--keys", keys, "--limit", "1"}, &sweepOut, &sweepDiag); e != nil {
		t.Fatal(e)
	}
	var sweep bootstrap.ReplaySweepReport
	if e = json.Unmarshal(sweepOut.Bytes(), &sweep); e != nil || len(sweep.Items) != 1 || sweep.Items[0].Status != "verified" || sweep.RestoreReady {
		t.Fatal(sweep, e)
	}
	unknown := filepath.Join(root, "unknown")
	if e = os.WriteFile(unknown, nil, 0600); e != nil {
		t.Fatal(e)
	}
	sweepOut.Reset()
	if e = run([]string{"backup", "sweep-replay", "--work-parent", work, "--keys", keys, "--apply"}, &sweepOut, &sweepDiag); e == nil {
		t.Fatal("unsafe sweep accepted")
	}
	if e = json.Unmarshal(sweepOut.Bytes(), &sweep); e != nil || sweep.Rejected != 1 || sweep.Items[0].Status != "rejected" {
		t.Fatal(sweep, e)
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	var reclaimOut, reclaimDiag bytes.Buffer
	if e = run([]string{"backup", "reclaim-with-keys", "--input", backup, "--keys", keys, "--apply"}, &reclaimOut, &reclaimDiag); e != nil {
		t.Fatal(e)
	}
	var retained bootstrap.BackupReport
	if e = json.Unmarshal(reclaimOut.Bytes(), &retained); e != nil || retained.Expired || retained.Applied || retained.RestoreReady {
		t.Fatal(retained, e)
	}
	for _, apply := range []bool{false, true} {
		args := []string{"backup", "reclaim-replay", "--input", root, "--keys", keys}
		if apply {
			args = append(args, "--apply")
		}
		var out, diag bytes.Buffer
		if e = run(args, &out, &diag); e != nil {
			t.Fatal(e)
		}
		var report bootstrap.ReplayReclaimReport
		if e = json.Unmarshal(out.Bytes(), &report); e != nil || report.Applied != apply || report.RestoreReady || report.PlannedFiles < 3 {
			t.Fatal(report, e)
		}
		if !apply {
			if _, e = os.Stat(filepath.Join(root, "keys/master-000001.key")); e != nil {
				t.Fatal("preview changed key", e)
			}
		}
	}
	if _, e = os.Stat(root); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	for _, extra := range [][]string{{"--budget", "0s"}, {"--budget", "6m"}, {"--limit", "0"}, {"--after", "../escape"}, {"--config", config}, {"unexpected"}} {
		var out, diag bytes.Buffer
		args := append([]string{"backup", "sweep-replay", "--work-parent", work, "--keys", keys}, extra...)
		if e = run(args, &out, &diag); e == nil {
			t.Fatal(args, "accepted")
		}
	}
	for _, extra := range [][]string{{"--interval", "1s"}, {"--interval", "25h"}, {"--budget", "0s"}, {"--limit", "129"}, {"--config", config}, {"--after", ".backup-replay-a"}, {"unexpected"}} {
		var out, diag bytes.Buffer
		args := append([]string{"backup", "watch-replay", "--work-parent", work, "--keys", keys}, extra...)
		if e = run(args, &out, &diag); e == nil {
			t.Fatal(args, "accepted")
		}
	}
	for _, args := range [][]string{{"backup", "reclaim-replay"}, {"backup", "reclaim-replay", "--input", root}, {"backup", "reclaim-replay", "--input", root, "--keys", keys, "--config", config}, {"backup", "reclaim-replay", "--input", root, "--keys", keys, "unexpected"}, {"backup", "reclaim-replay", "--input", strconv.Quote(root), "--keys", keys}} {
		var out, diag bytes.Buffer
		if e = run(args, &out, &diag); e == nil || out.Len() != 0 {
			t.Fatal(args, e)
		}
	}
}
