// 空き容量、7日境界、削除順、DAT/原本の実回収と再起動を実Repositoryで確認する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"oimobbs/internal/disclosure"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

func pressureRepositoryFixture(t *testing.T) (Config, *Repository, domain.ID, uint64) {
	t.Helper()
	cfg, r, info := postingRepositoryFixture(t)
	if _, e := r.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = r.Close() })
	if e = r.EnableStoragePressureReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	b := r.posting[info.ID]
	b.expiryCancel()
	<-b.expiryDone
	at := time.Now().Add(-8 * 24 * time.Hour)
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return at }
		defer func() { b.clock = time.Now }()
		return b.post(0, persistentFrameAt(t, at), []byte(`{"fixture":true}`)), nil
	})
	if e != nil || value.(RepositoryPostingResult).Status != store.Durable {
		t.Fatal(value, e)
	}
	return cfg, r, info.ID, value.(RepositoryPostingResult).ThreadKey
}

func TestStoragePressureThresholdAndOrder(t *testing.T) {
	s := PostingCapacityStatus{Known: true, FloorBytes: 10 << 30, AvailableBytes: 11 << 30}
	if !storagePressureNeeded(s, false) {
		t.Fatal("early reclamation should start before posting floor")
	}
	s.AvailableBytes = 12 << 30
	if storagePressureNeeded(s, false) || !storagePressureNeeded(s, true) {
		t.Fatal("missing hysteresis")
	}
	s.AvailableBytes = 13 << 30
	if storagePressureNeeded(s, true) {
		t.Fatal("failed to stop")
	}
	s.Known = false
	if storagePressureNeeded(s, true) {
		t.Fatal("unknown capacity permitted deletion")
	}
	rows := []pressureCandidate{{key: 1, last: 10, full: true}, {key: 2, last: 30}, {key: 3, last: 20}, {key: 4, last: 5, full: true}}
	sort.Slice(rows, func(i, j int) bool { return pressureCandidateLess(rows[i], rows[j]) })
	for i, want := range []uint64{3, 2, 4, 1} {
		if rows[i].key != want {
			t.Fatal(rows)
		}
	}
}

func TestStoragePressureReclaimsBeforeExpiryAndRestarts(t *testing.T) {
	cfg, r, id, key := pressureRepositoryFixture(t)
	b := r.posting[id]
	before := requiredStartupFiles(t, cfg.DataDir)
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: 30 << 30}, nil
	}
	if e := r.SweepStoragePressure(t.Context()); e != nil {
		t.Fatal(e)
	}
	if b.threads[key].Reclaimed() {
		t.Fatal("deleted without pressure")
	}
	// 回収writer以外のcontrol変更もない。
	after := requiredStartupFiles(t, cfg.DataDir)
	if len(before) != len(after) {
		t.Fatal("normal capacity wrote new files")
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: 10 << 30}, nil
	}
	for range 6 {
		if e := r.SweepStoragePressure(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
	if !b.threads[key].Reclaimed() || r.StoragePressure().DroppedThreads != 1 || r.StoragePressure().RemovedOriginals != 2 {
		t.Fatal(r.StoragePressure())
	}
	if _, e := os.Stat(filepath.Join(b.threadsDir, fmt.Sprint(key))); !os.IsNotExist(e) {
		t.Fatal("DAT still exists", e)
	}
	proof, e := readBodyReclamation(b.deletions[key].State(), id, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil || proof.Kind != "pressure" || proof.At >= proof.Expires {
		t.Fatal(proof, e)
	}
	for _, j := range b.journals {
		rows, e := j.RequiredRetirements()
		if e != nil || len(rows) != 2 {
			t.Fatal(rows, e)
		}
		for _, row := range rows {
			if !row.Pressure || row.Until <= proof.At {
				t.Fatal("original deadline changed", row)
			}
		}
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("restart failed", e)
	}
	defer reopened.Close()
	if p := reopened.posting[id].threads[key]; p == nil || !p.Reclaimed() {
		t.Fatal("deleted thread revived")
	}
	if snapshot, e := reopened.Thread(t.Context(), id, key); e != nil || snapshot != nil {
		t.Fatal("deleted DAT exposed", snapshot, e)
	}
}

func TestStoragePressureSevenDayBoundary(t *testing.T) {
	_, r, id, key := pressureRepositoryFixture(t)
	b := r.posting[id]
	value, e := b.worker.Submit(t.Context(), func() (any, error) { last, _, _, _ := b.threads[key].StoragePressureState(); return last, nil })
	if e != nil {
		t.Fatal(e)
	}
	last := value.(domain.Time)
	for _, tc := range []struct {
		delta time.Duration
		want  int
	}{{storagePressureIdle - time.Nanosecond, 0}, {storagePressureIdle, 1}} {
		rows, e := r.pressureCandidates(t.Context(), last+domain.Time(tc.delta))
		if e != nil || len(rows) != tc.want {
			t.Fatal(tc, rows, e)
		}
	}
}

func TestStoragePressurePreservesCaseIntent(t *testing.T) {
	_, r, id, key := pressureRepositoryFixture(t)
	now := time.Now()
	scope := disclosure.Scope{Board: id, Thread: domain.U64(key), From: domain.Time(now.Add(-9 * 24 * time.Hour).UnixNano()), To: domain.Time(now.UnixNano()), Records: []domain.ID{}}
	r.mu.Lock()
	rows, e := r.collectEvidence(t.Context(), scope)
	actor := domain.NewID()
	if e == nil {
		var c disclosure.Case
		c, e = r.evidenceCases.Create(disclosure.Case{Number: "pressure-hold", Reason: "容量回収から保全", Scope: scope, Until: domain.Time(now.Add(24 * time.Hour).UnixNano())}, actor, `"evidence:new"`, "create", now)
		if e == nil {
			_, e = r.evidenceCases.PrepareHold(c.ID, actor, c.ETag(), "hold", "原本保全", rows, now)
		}
	}
	r.mu.Unlock()
	if e != nil || len(rows) != 1 {
		t.Fatal(len(rows), e)
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: 10 << 30}, nil
	}
	if e = r.SweepStoragePressure(t.Context()); e != nil {
		t.Fatal(e)
	}
	if r.posting[id].threads[key].Reclaimed() || r.StoragePressure().StopReason != "protected" {
		t.Fatal("case source dropped", r.StoragePressure())
	}
}

func TestStoragePressureInterruptedRecovery(t *testing.T) {
	for _, stage := range []string{"pressure:intent", "expiry:applied", "reclaim:proof", "reclaim:running"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, id, key := pressureRepositoryFixture(t)
			b := r.posting[id]
			b.deletionCheckpoint = func(at string) error {
				if at == stage {
					return errors.New("interruption")
				}
				return nil
			}
			r.packSpace = func(string) (platform.DiskSpace, error) {
				return platform.DiskSpace{Total: 100 << 30, Available: 10 << 30}, nil
			}
			if e := r.SweepStoragePressure(t.Context()); e == nil {
				t.Fatal("checkpoint not reached")
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal("restart", e)
			}
			defer reopened.Close()
			if p := reopened.posting[id].threads[key]; p == nil || !p.Reclaimed() {
				t.Fatal("interrupted drop revived")
			}
			if e = reopened.EnableStoragePressureReclamation(t.Context()); e != nil {
				t.Fatal(e)
			}
			reopened.packSpace = r.packSpace
			for range 5 {
				if e = reopened.SweepStoragePressure(t.Context()); e != nil {
					t.Fatal(e)
				}
			}
			total := 0
			for _, j := range reopened.posting[id].journals {
				rows, e := j.RequiredRetirements()
				if e != nil {
					t.Fatal(e)
				}
				total += len(rows)
			}
			if total != 2 {
				t.Fatal("original recovery incomplete", total, reopened.StoragePressure())
			}
		})
	}
}

func TestStoragePressureKeepsOtherBoardPostingAvailable(t *testing.T) {
	_, r, id, _ := pressureRepositoryFixture(t)
	other, e := r.CreateBoard(t.Context(), "other", "別の板")
	if e != nil {
		t.Fatal(e)
	}
	reached, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	r.posting[id].deletionCheckpoint = func(stage string) error {
		if stage == "pressure:intent" {
			close(reached)
			<-release
		}
		return nil
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: (10 << 30) + (512 << 20)}, nil
	}
	done := make(chan error, 1)
	go func() { done <- r.SweepStoragePressure(t.Context()) }()
	select {
	case <-reached:
	case e := <-done:
		t.Fatal("reclamation did not start", e)
	case <-time.After(5 * time.Second):
		t.Fatal("reclamation stalled")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := r.Post(ctx, other.ID, 0, persistentFrame(t), []byte(`{"fixture":true}`))
	unblock()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	if result.Status != store.Durable {
		t.Fatal("other board posting waited for reclamation", result)
	}
	if snapshot, e := r.Thread(t.Context(), other.ID, result.ThreadKey); e != nil || snapshot == nil {
		t.Fatal("other post unavailable", snapshot, e)
	}
}

func TestStoragePressureHTTPAndBackupReplay(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	info, e := r.CreateBoard(t.Context(), "pressure", "容量回収")
	if e != nil {
		t.Fatal(e)
	}
	if e = r.EnableStoragePressureReclamation(t.Context()); e != nil {
		t.Fatal(e)
	}
	b := r.posting[info.ID]
	b.expiryCancel()
	<-b.expiryDone
	_, e = b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return time.Now().Add(-8 * 24 * time.Hour) }
		return nil, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	posted, e := sendForm(server, url.Values{"bbs": {"pressure"}, "subject": {"古いスレッド"}, "MESSAGE": {"capacity-private-original"}, "oimo_request_id": {"pressure-http-old-001"}})
	_, resetErr := b.worker.Submit(t.Context(), func() (any, error) { b.clock = time.Now; return nil, nil })
	if e != nil || resetErr != nil || !posted.Accepted {
		t.Fatal(posted, e, resetErr)
	}
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: (10 << 30) + (512 << 20)}, nil
	}
	for range 5 {
		if e = r.SweepStoragePressure(t.Context()); e != nil {
			t.Fatal(e)
		}
	}
	if snapshot, e := r.Thread(t.Context(), info.ID, posted.Key); e != nil || snapshot != nil {
		t.Fatal("dropped HTTP thread still visible", e)
	}
	survivor, e := sendForm(server, url.Values{"bbs": {"pressure"}, "subject": {"新しいスレッド"}, "MESSAGE": {"survivor-current-post"}, "oimo_request_id": {"pressure-http-new-002"}})
	if e != nil || !survivor.Accepted {
		t.Fatal("new HTTP post failed", survivor, e)
	}
	if snapshot, e := r.Thread(t.Context(), info.ID, survivor.Key); e != nil || snapshot == nil {
		t.Fatal("new HTTP post missing", e)
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	online := filepath.Join(parent, "online")
	if _, e = r.CopyBoardBackup(t.Context(), info.ID, online, OnlineBackupGroupOptions{}); e != nil {
		t.Fatal("online backup", e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	body, keys, work := filepath.Join(parent, "body"), filepath.Join(parent, "keys"), filepath.Join(parent, "work")
	if _, e = CaptureOfflineBackup(t.Context(), cfg, body); e != nil {
		t.Fatal(e)
	}
	if _, e = ExportBackupKeys(t.Context(), cfg, body, keys); e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	report, e := VerifyBackupReplay(t.Context(), body, keys, work)
	if e != nil || !report.Replayed {
		t.Fatal("pressure backup replay", report, e)
	}
}
