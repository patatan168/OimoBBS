// 空き容量不足だけを定期バックアップの延期にし、別の保存エラーを隠さないことを検証する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/platform"
	"path/filepath"
	"testing"
	"time"
)

func TestOnlineBackupCapacityDeferral(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false}, {ErrOnlineBackupCapacity, true}, {fmt.Errorf("capture: %w", ErrOnlineBackupCapacity), true},
		{errors.Join(ErrOnlineBackupCapacity, ErrOnlineBackupCapacity), true},
		{errors.Join(ErrOnlineBackupCapacity, io.ErrShortWrite), false}, {io.ErrShortWrite, false},
	} {
		if got := onlyOnlineBackupCapacity(tc.err); got != tc.want {
			t.Fatalf("%v: %v", tc.err, got)
		}
	}
	cfg, repo := adminFixture(t)
	defer repo.Close()
	o := BackupPreparationMaintenanceOptions{CopyParent: expiredSweepParent(t), KeysParent: expiredSweepParent(t), PartialPlanParent: expiredSweepParent(t), PartialKeysPlanParent: expiredSweepParent(t), KeysPlanParent: expiredSweepParent(t), PairPlanParent: expiredSweepParent(t), WorkParent: expiredSweepParent(t), ControlParent: expiredSweepParent(t), Interval: time.Hour, Budget: time.Minute}
	o.TrustInstance = onlineOutput(t, "trust.json")
	raw, err := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeNew(o.TrustInstance, raw); err != nil {
		t.Fatal(err)
	}
	o.Apply = true
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	// 空き容量をゼロにし、実際の捕捉予約から容量エラーを発生させる。
	repo.packSpace = func(string) (platform.DiskSpace, error) { return platform.DiskSpace{Total: 2 << 30}, nil }
	reports := 0
	err = repo.RunOnlineBackupMaintenance(ctx, o, OnlineBackupSiteOptions{}, func(report BackupPreparationMaintenanceReport) error {
		reports++
		if report.Status != "deferred_capacity" {
			t.Fatalf("unexpected report: %+v", report)
		}
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || reports != 1 {
		t.Fatal(reports, err)
	}
}
