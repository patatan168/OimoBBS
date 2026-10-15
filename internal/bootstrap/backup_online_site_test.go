// 全サイト捕捉の並行投稿・構造変更・監査不足・上限・取消を稼働Repositoryで確認する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/store"
)

func syncOnlineAudit(t *testing.T, r *Repository) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	budget := store.HistoryBudget{Bytes: 64 << 20, Frames: 200000}
	if e := r.catchUpAudit(context.Background(), &budget); e != nil {
		t.Fatal(e)
	}
}

func onlineOutput(t *testing.T, name string) string {
	t.Helper()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	return filepath.Join(parent, name)
}

func TestOnlineSiteAssembly(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	a, e := r.CreateBoard(ctx, "assemblya", "集約A")
	if e != nil {
		t.Fatal(e)
	}
	b, e := r.CreateBoard(ctx, "assemblyb", "集約B")
	if e != nil {
		t.Fatal(e)
	}
	sa := formServer(t, r, siteID(r.site.State()), a.ID)
	defer sa.Close()
	sb := formServer(t, r, siteID(r.site.State()), b.ID)
	defer sb.Close()
	first, e := sendForm(sa, url.Values{"bbs": {"assemblya"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"assembly-first-a"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	second, e := sendForm(sb, url.Values{"bbs": {"assemblyb"}, "subject": {"second"}, "MESSAGE": {"second"}, "oimo_request_id": {"assembly-first-b"}})
	if e != nil || !second.Accepted {
		t.Fatal(second, e)
	}
	syncOnlineAudit(t, r)
	target := onlineOutput(t, "site")
	cut, e := r.assembleOnlineBackup(ctx, target, OnlineBackupSiteOptions{}, time.Now, func(stage string) error {
		if stage == "copy_part" {
			if _, err := r.PinSiteBackup(ctx, OnlineBackupCopyOptions{}); !errors.Is(err, ErrOnlineBackupBusy) {
				return fmt.Errorf("shared slot: %v", err)
			}
			reply, err := sendForm(sa, url.Values{"bbs": {"assemblya"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"after pin"}, "oimo_request_id": {"assembly-after-a"}})
			if err != nil || !reply.Accepted {
				return fmt.Errorf("concurrent post: %v", err)
			}
		}
		return nil
	}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if cut.RestoreReady || cut.Site != siteID(r.site.State()) || len(cut.Captures) < 10 || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(cut)
	}
	log, e := store.OpenThread(filepath.Join(target, "thread", a.ID.String()), a.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	if log.State().Revision != 1 {
		t.Fatal("copy advanced")
	}
	log.Close()
	if _, e = os.Stat(filepath.Join(target, "manifest.json")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	syncOnlineAudit(t, r)
	changed := false
	_, e = r.assembleOnlineBackup(ctx, onlineOutput(t, "changed"), OnlineBackupSiteOptions{}, time.Now, func(stage string) error {
		if stage == "site_pinned" && !changed {
			changed = true
			_, err := r.CreateBoard(ctx, "assemblyc", "集約C")
			return err
		}
		return nil
	}, nil)
	if !errors.Is(e, ErrOnlineBackupChanged) {
		t.Fatal(e)
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("reservation leak")
	}
}

func TestOnlineSiteAssemblyFailures(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	if _, e := r.CreateBoard(ctx, "assembly", "捕捉失敗"); e != nil {
		t.Fatal(e)
	}
	if cut, e := r.AssembleOnlineBackup(ctx, onlineOutput(t, "audit-missing"), OnlineBackupSiteOptions{}); e == nil || len(cut.Captures) != 0 {
		t.Fatal(cut, e)
	}
	syncOnlineAudit(t, r)
	for _, o := range []OnlineBackupSiteOptions{{MaxOwners: 1}, {MaxOwners: 257}, {MaxBoards: 65}, {MaxBytes: 1}} {
		if cut, e := r.AssembleOnlineBackup(ctx, onlineOutput(t, "limit"), o); e == nil || len(cut.Captures) != 0 {
			t.Fatal(o, cut, e)
		}
		if r.PostingCapacity().ReservedBytes != 0 {
			t.Fatal("limit leak")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	target := onlineOutput(t, "partial")
	cut, e := r.assembleOnlineBackup(cancelled, target, OnlineBackupSiteOptions{}, time.Now, func(stage string) error {
		if stage == "copy_part" {
			cancel()
		}
		return nil
	}, nil)
	if !errors.Is(e, context.Canceled) || len(cut.Captures) != 0 || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(cut, e)
	}
	if _, e = r.AssembleOnlineBackup(ctx, onlineOutput(t, "retry"), OnlineBackupSiteOptions{}); e != nil {
		t.Fatal(e)
	}
}

func TestOnlineBackupPreparation(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "onlineprepare", "完成捕捉")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	first, e := sendForm(server, url.Values{"bbs": {"onlineprepare"}, "subject": {"online"}, "MESSAGE": {"saved"}, "oimo_request_id": {"online-prepare-first"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	syncOnlineAudit(t, r)
	body, keys, trust, bodyPlan, keysPlan, pairPlan := onlineOutput(t, "body"), onlineOutput(t, "keys"), onlineOutput(t, "trust.json"), onlineOutput(t, "body-plan.json"), onlineOutput(t, "keys-plan.json"), onlineOutput(t, "pair-plan.json")
	work := filepath.Dir(onlineOutput(t, "work-unused"))
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(trust, raw); e != nil {
		t.Fatal(e)
	}
	report, e := r.PrepareOnlineBackup(ctx, body, keys, work, OnlineBackupPreparationOptions{TrustInstance: trust, PartialPlan: bodyPlan, PartialKeysPlan: keysPlan, PairPlan: pairPlan})
	if e != nil {
		t.Fatal(report, e)
	}
	if !report.Complete || report.RestoreReady || !report.Replay.Replayed || !*report.PairPlanned {
		t.Fatal(report)
	}
	m, _, e := r.loadBackup(body)
	if e != nil {
		t.Fatal(e)
	}
	if m.Schema != 7 || m.Mode != "online_candidate" {
		t.Fatal(m)
	}
	reply, e := sendForm(server, url.Values{"bbs": {"onlineprepare"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"still running"}, "oimo_request_id": {"online-prepare-after"}})
	if e != nil || reply.Number != 2 {
		t.Fatal(reply, e)
	}
	if _, e = VerifyBackupWithKeys(ctx, body, keys); e != nil {
		t.Fatal(e)
	}
	if _, e = ReclaimOnlinePartialBackup(ctx, body, trust, bodyPlan, true); e == nil {
		t.Fatal("completed body accepted as partial")
	}
	if _, e = ReclaimBackupPair(ctx, body, keys, trust, pairPlan, false); e != nil {
		t.Fatal(e)
	}

	bundle, e := loadBackupKeys(ctx, keys)
	if e != nil {
		t.Fatal(e)
	}
	bundle.Mode = "offline_keys"
	signing, e := backupKeysKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(signing[:])
	wrong, e := encodeBackupKeys(bundle, signing)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(keys, "bundle.json"), wrong, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBackupWithKeys(ctx, body, keys); e == nil {
		t.Fatal("online body accepted offline key purpose")
	}
	if _, e = VerifyBackupReplay(ctx, body, keys, work); e == nil {
		t.Fatal("online replay accepted offline key purpose")
	}
}

func TestOnlinePartialReclamation(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	if _, e := r.CreateBoard(ctx, "partialonline", "途中出力"); e != nil {
		t.Fatal(e)
	}
	syncOnlineAudit(t, r)
	target, trust, plan := onlineOutput(t, "partial"), onlineOutput(t, "trust.json"), onlineOutput(t, "plan.json")
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(trust, raw); e != nil {
		t.Fatal(e)
	}
	_, e = r.captureOnlineBackup(ctx, target, trust, plan, OnlineBackupSiteOptions{}, time.Now, func(stage string) error {
		if stage == "online_plan_synced" {
			return context.Canceled
		}
		return nil
	})
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if report, e := ReclaimOnlinePartialBackup(ctx, target, trust, plan, true); e != nil || report.Applied {
		t.Fatal(report, e)
	}
	if e = writeNew(filepath.Join(target, "unknown"), []byte("keep")); e != nil {
		t.Fatal(e)
	}
	if _, e = reclaimOnlinePartial(ctx, target, trust, plan, true, func() time.Time { return time.Now().Add(25 * time.Hour) }); e == nil {
		t.Fatal("unknown input removed")
	}
	if e = os.Remove(filepath.Join(target, "unknown")); e != nil {
		t.Fatal(e)
	}
	if report, e := reclaimOnlinePartial(ctx, target, trust, plan, true, func() time.Time { return time.Now().Add(25 * time.Hour) }); e != nil || !report.Applied {
		t.Fatal(report, e)
	}
}

func TestOnlineBackupMaintenance(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	if _, e := r.CreateBoard(ctx, "onlinewatch", "定期捕捉"); e != nil {
		t.Fatal(e)
	}
	o := BackupPreparationMaintenanceOptions{CopyParent: expiredSweepParent(t), KeysParent: expiredSweepParent(t), PartialPlanParent: expiredSweepParent(t), PartialKeysPlanParent: expiredSweepParent(t), KeysPlanParent: expiredSweepParent(t), PairPlanParent: expiredSweepParent(t), WorkParent: expiredSweepParent(t), ControlParent: expiredSweepParent(t), Interval: time.Hour, Budget: time.Minute}
	o.TrustInstance = onlineOutput(t, "trust.json")
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	if e = writeNew(o.TrustInstance, raw); e != nil {
		t.Fatal(e)
	}
	if report, e := r.PrepareNextOnlineBackup(ctx, o, OnlineBackupSiteOptions{}); e != nil || report.Status != "preview" || report.Name != "" {
		t.Fatal(report, e)
	}
	o.Apply = true
	report, e := r.PrepareNextOnlineBackup(ctx, o, OnlineBackupSiteOptions{})
	if e != nil || !report.Preparation.Complete {
		t.Fatal(report, e)
	}
	pin, e := r.PinSiteBackup(ctx, OnlineBackupCopyOptions{})
	if e != nil {
		t.Fatal(e)
	}
	busy, e := r.PrepareNextOnlineBackup(ctx, o, OnlineBackupSiteOptions{})
	pin.Close()
	if e != nil || busy.Status != "deferred_busy" {
		t.Fatal(busy, e)
	}
	stop := errors.New("stop after first report")
	e = r.RunOnlineBackupMaintenance(ctx, o, OnlineBackupSiteOptions{}, func(report BackupPreparationMaintenanceReport) error {
		if !report.Preparation.Complete {
			t.Fatal(report)
		}
		if _, e := r.PrepareNextOnlineBackup(ctx, o, OnlineBackupSiteOptions{}); e == nil {
			t.Fatal("double scheduler accepted")
		}
		return stop
	})
	if !errors.Is(e, stop) {
		t.Fatal(e)
	}
}
