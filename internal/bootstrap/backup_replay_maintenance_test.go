// 定期回収のページ進行・再巡回・排他・中断を、実時間待機なしで検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func TestReplayMaintenanceCycleAndLock(t *testing.T) {
	backup, keys, root := staleReplayFixture(t)
	parent := filepath.Dir(root)
	key, e := replayCleanupKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	raw, e := readPrivate(filepath.Join(root, backupReplayGate), replayCleanupLimit)
	if e != nil {
		t.Fatal(e)
	}
	p, e := decodeReplayCleanupPlan(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimBackupReplay(context.Background(), root, keys, true); e != nil {
		t.Fatal(e)
	}
	a := partialSweepRoot(t, parent, ".backup-replay-a", keys, p)
	b := partialSweepRoot(t, parent, ".backup-replay-b", keys, p)
	c := partialSweepRoot(t, parent, ".backup-replay-c", keys, p)
	busy, e := platform.Lock(a)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if busy != nil {
			_ = platform.Unlock(busy)
		}
	}()
	unknown := filepath.Join(b, "unknown")
	if e = os.WriteFile(unknown, nil, 0600); e != nil {
		t.Fatal(e)
	}
	o := ReplayMaintenanceOptions{parent, keys, 1, time.Minute, time.Second * 30, true}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reports := []ReplayMaintenanceReport{}
	waits := 0
	wait := func(ctx context.Context, d time.Duration) error {
		waits++
		if d != o.Interval {
			t.Fatal(d)
		}
		if waits == 3 {
			if e := platform.Unlock(busy); e != nil {
				t.Fatal(e)
			}
			busy = nil
			if e := os.Remove(unknown); e != nil {
				t.Fatal(e)
			}
		}
		if waits == 6 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	emit := func(report ReplayMaintenanceReport) error {
		reports = append(reports, report)
		if len(reports) == 1 {
			if _, e := platform.Lock(parent); e == nil {
				t.Fatal("parent daemon lock missing")
			}
			if e := RunBackupReplayMaintenance(ctx, o, func(ReplayMaintenanceReport) error { return nil }); e == nil {
				t.Fatal("second daemon accepted")
			}
		}
		return nil
	}
	if e = runBackupReplayMaintenance(ctx, o, emit, wait, SweepBackupReplay); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if len(reports) != 6 || reports[0].Sweep.Busy != 1 || reports[1].Status != "needs_attention" || reports[2].Sweep.Items[0].Name != filepath.Base(c) || reports[3].Sweep.Items[0].Name != filepath.Base(a) || reports[4].Sweep.Items[0].Name != filepath.Base(b) || len(reports[5].Sweep.Items) != 0 {
		t.Fatal(reports)
	}
	for _, path := range []string{a, b, c} {
		if _, e = os.Stat(path); !os.IsNotExist(e) {
			t.Fatal("work remains", path, e)
		}
	}
	if _, e = VerifyBackupWithKeys(context.Background(), backup, keys); e != nil {
		t.Fatal(e)
	}
	lock, e := platform.Lock(parent)
	if e != nil {
		t.Fatal("daemon lock leaked", e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*ReplayMaintenanceOptions){func(v *ReplayMaintenanceOptions) { v.Limit = 0 }, func(v *ReplayMaintenanceOptions) { v.Interval = time.Second }, func(v *ReplayMaintenanceOptions) { v.Budget = 6 * time.Minute }} {
		bad := o
		mutate(&bad)
		if e = RunBackupReplayMaintenance(context.Background(), bad, emit); e == nil {
			t.Fatal("invalid options accepted")
		}
	}
	if e = RunBackupReplayMaintenance(context.Background(), o, nil); e == nil {
		t.Fatal("nil writer accepted")
	}
	stop := errors.New("report failed")
	if e = RunBackupReplayMaintenance(context.Background(), o, func(ReplayMaintenanceReport) error { return stop }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	// 予算超過時は最後に完了した位置から次回へ引き継ぐ。
	calls := 0
	sweep := func(ctx context.Context, parent, keys, after string, limit int, apply bool) (ReplaySweepReport, error) {
		calls++
		if calls == 1 {
			return ReplaySweepReport{Next: ".backup-replay-cursor", More: true}, context.DeadlineExceeded
		}
		if after != ".backup-replay-cursor" {
			t.Fatal(after)
		}
		return ReplaySweepReport{}, stop
	}
	statuses := []string{}
	e = runBackupReplayMaintenance(context.Background(), o, func(r ReplayMaintenanceReport) error { statuses = append(statuses, r.Status); return nil }, func(context.Context, time.Duration) error { return nil }, sweep)
	if !errors.Is(e, stop) || len(statuses) != 2 || statuses[0] != "budget_exhausted" || statuses[1] != "failed" {
		t.Fatal(statuses, e)
	}
	// 用途が変わった鍵束や親へ、同じプロセスの巡回を引き継がない。
	bundlePath := filepath.Join(keys, "bundle.json")
	original, e := os.ReadFile(bundlePath)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	e = runBackupReplayMaintenance(context.Background(), o, func(ReplayMaintenanceReport) error { count++; return nil }, func(context.Context, time.Duration) error {
		return os.WriteFile(bundlePath, append(append([]byte{}, original...), '\n'), 0600)
	}, SweepBackupReplay)
	if e == nil || count != 1 {
		t.Fatal("bundle replacement accepted", count, e)
	}
	if e = os.WriteFile(bundlePath, original, 0600); e != nil {
		t.Fatal(e)
	}
	count = 0
	e = runBackupReplayMaintenance(context.Background(), o, func(ReplayMaintenanceReport) error { count++; return nil }, func(context.Context, time.Duration) error {
		if e := os.Rename(parent, parent+"-moved"); e != nil {
			return e
		}
		return os.Mkdir(parent, 0700)
	}, SweepBackupReplay)
	if e == nil || count != 1 {
		t.Fatal("parent replacement accepted", count, e)
	}
}
