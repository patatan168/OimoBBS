// 期限切れ/期限内の混在、独立した鍵束、拒否の保持、ページ送りと回収再開を検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiredBackupSweepPairs(t *testing.T) {
	cfg, output := backupFixture(t)
	copies := filepath.Dir(output)
	keys := expiredSweepParent(t)
	past := time.Now().Add(-25 * time.Hour)
	for _, pair := range []struct {
		name string
		at   time.Time
	}{{"a-expired", past}, {"b-fresh", time.Now()}} {
		clock := func() time.Time { return pair.at }
		root := filepath.Join(copies, pair.name)
		if _, e := captureOfflineBackup(context.Background(), cfg, root, clock, func(string) {}); e != nil {
			t.Fatal(e)
		}
		if _, e := exportBackupKeys(context.Background(), cfg, root, filepath.Join(keys, pair.name), clock, func(string) {}); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable"); e != nil {
		t.Fatal(e)
	}
	expired := filepath.Join(copies, "a-expired")
	preview, e := SweepExpiredBackups(context.Background(), copies, keys, "", 1, false)
	if e != nil || len(preview.Items) != 1 || preview.Items[0].Status != "expired" || !preview.More || preview.Next != "a-expired" || preview.RestoreReady || preview.Items[0].Reclaim.Verified {
		t.Fatal(preview, e)
	}
	fresh, e := SweepExpiredBackups(context.Background(), copies, keys, preview.Next, 1, true)
	if e != nil || fresh.More || len(fresh.Items) != 1 || fresh.Items[0].Status != "retained" {
		t.Fatal(fresh, e)
	}
	// 鍵束の名前だけ一致させても、異なるコピーへの束縛は拒否する。
	aKeys, bKeys := filepath.Join(keys, "a-expired"), filepath.Join(keys, "b-fresh")
	if e = os.Rename(aKeys, aKeys+"-saved"); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(bKeys, aKeys); e != nil {
		t.Fatal(e)
	}
	rejected, e := SweepExpiredBackups(context.Background(), copies, keys, "", 1, true)
	if !errors.Is(e, ErrBackupSweepRejected) || rejected.Rejected != 1 || rejected.Items[0].Reclaim != nil {
		t.Fatal(rejected, e)
	}
	if _, e = os.Stat(filepath.Join(expired, "manifest.json")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(aKeys, bKeys); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(aKeys+"-saved", aKeys); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(bKeys, bKeys+"-saved"); e != nil {
		t.Fatal(e)
	}
	missing, e := SweepExpiredBackups(context.Background(), copies, keys, "a-expired", 1, true)
	if !errors.Is(e, ErrBackupSweepRejected) || missing.Items[0].Status != "rejected" {
		t.Fatal(missing, e)
	}
	if _, e = os.Stat(filepath.Join(copies, "b-fresh", "manifest.json")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(bKeys+"-saved", bKeys); e != nil {
		t.Fatal(e)
	}
	unknown := filepath.Join(expired, "unlisted")
	if e = os.WriteFile(unknown, nil, 0600); e != nil {
		t.Fatal(e)
	}
	rejected, e = SweepExpiredBackups(context.Background(), copies, keys, "", 2, true)
	if !errors.Is(e, ErrBackupSweepRejected) || rejected.Rejected != 1 || rejected.Next != "b-fresh" || rejected.Items[1].Status != "retained" {
		t.Fatal(rejected, e)
	}
	if e = os.Remove(unknown); e != nil {
		t.Fatal(e)
	}
	// 通常fileと外部へのリンクも対象に含め、鍵がないまま削除しない。
	for _, name := range []string{"c-file", "d-link"} {
		root := filepath.Join(copies, name)
		if name == "c-file" {
			e = os.WriteFile(root, nil, 0600)
		} else {
			e = os.Symlink(expired, root)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	rejected, e = SweepExpiredBackups(context.Background(), copies, keys, "b-fresh", 16, true)
	if !errors.Is(e, ErrBackupSweepRejected) || rejected.Rejected != 2 || rejected.Next != "d-link" {
		t.Fatal(rejected, e)
	}
	for _, name := range []string{"c-file", "d-link"} {
		if _, e = os.Lstat(filepath.Join(copies, name)); e != nil {
			t.Fatal(e)
		}
	}
	interruptedCtx, interrupt := context.WithCancel(context.Background())
	calls := 0
	interrupted, err := sweepExpiredBackups(interruptedCtx, copies, keys, "", 2, false, func() time.Time {
		calls++
		if calls == 2 {
			interrupt()
		}
		return time.Now()
	})
	interrupt()
	if !errors.Is(err, context.Canceled) || interrupted.Next != "a-expired" || len(interrupted.Items) != 1 || !interrupted.More {
		t.Fatal(interrupted, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = SweepExpiredBackups(ctx, copies, keys, "", 16, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	stop := errors.New("stop after payload unlink")
	if _, e = reclaimBackupWithKeys(context.Background(), expired, aKeys, true, time.Now, func(string) error { return stop }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	resumed, e := SweepExpiredBackups(context.Background(), copies, keys, "", 1, true)
	if e != nil || resumed.Items[0].Status != "reclaimed" || !resumed.Items[0].Reclaim.Applied {
		t.Fatal(resumed, e)
	}
	if _, e = os.Stat(expired); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("body remains", e)
	}
	for _, name := range []string{"a-expired", "b-fresh"} {
		if _, e = loadBackupKeys(context.Background(), filepath.Join(keys, name)); e != nil {
			t.Fatal("keys changed", e)
		}
	}
}

func TestExpiredBackupSweepBounds(t *testing.T) {
	copies, keys := expiredSweepParent(t), expiredSweepParent(t)
	for _, input := range []struct {
		keys, after string
		limit       int
	}{{copies, "", 1}, {filepath.Join(copies, "nested"), "", 1}, {keys, "../escape", 1}, {keys, ".hidden", 1}, {keys, "", 0}, {keys, "", 129}} {
		if _, e := SweepExpiredBackups(context.Background(), copies, input.keys, input.after, input.limit, true); e == nil {
			t.Fatal(input, "accepted")
		}
	}
	if e := os.WriteFile(filepath.Join(copies, ".ignored"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	empty, e := SweepExpiredBackups(context.Background(), copies, keys, "", 16, true)
	if e != nil || len(empty.Items) != 0 || empty.More {
		t.Fatal(empty, e)
	}
	// 隠しentryも親全体の上限へ算入し、処理を一件も開始しない。
	for i := 0; i < replaySweepEntryLimit; i++ {
		if e = os.WriteFile(filepath.Join(copies, time.Unix(int64(i), 0).Format("150405")), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	bounded, e := SweepExpiredBackups(context.Background(), copies, keys, "", 16, true)
	if e == nil || len(bounded.Items) != 0 || bounded.Next != "" {
		t.Fatal(bounded, e)
	}
}

func expiredSweepParent(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	if e := os.Chmod(p, 0700); e != nil {
		t.Fatal(e)
	}
	return p
}
