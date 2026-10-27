// 製品の永続欠測snapshot、再起動・保存先障害・容量予約と欠落拒否を実fileで検査する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestOptionalLossProductRestart(t *testing.T) {
	cfg, r := adminFixture(t)
	server := optionalProductServer(t, r)
	if r.optionalQueue.Enqueue(evidence.OptionalRecord{}) {
		t.Fatal("invalid observation admitted")
	}
	r.snapshotOptionalLoss()
	status := r.OptionalHTTPLogs()
	if status.Loss.PersistFailed || !status.Loss.HasSnapshot || status.Loss.Known.Invalid != 1 || status.Loss.Summary.Clean {
		t.Fatal(status)
	}
	client := newAdminClient(t, r)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, body := client.request("GET", "/api/v1/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "known_losses") || !strings.Contains(body, "snapshot_only") || strings.Contains(body, "user_agent") || strings.Contains(body, "peer") {
		t.Fatal("private-free durable aggregate missing", response.StatusCode, body)
	}
	response, body = client.request("GET", "/maintenance", "", nil)
	if response.StatusCode != 200 || !strings.Contains(body, "再起動を越えた欠測集計") {
		t.Fatal("durable status HTML missing", response.StatusCode)
	}
	client.server.Close()
	server.Close()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), 32)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	saved, e := evidence.OpenOptionalLoss(filepath.Join(cfg.DataDir, "reports", optionalLossDir), status.Loss.Summary.Site, key)
	if e != nil {
		t.Fatal(e)
	}
	closed, ok := saved.Summary()
	saved.Close()
	if !ok || !closed.Clean || !closed.Queue.Closed || closed.Queue.Pending != 0 {
		t.Fatal(closed)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	again := r.OptionalHTTPLogs()
	if again.Queue.DroppedInvalid != 0 || again.Loss.Known.Invalid != 1 || again.Loss.Summary.KnownLossFrom != status.Loss.Summary.KnownLossFrom || again.Loss.Summary.UncleanBoots != 0 || again.Loss.Summary.Boot == status.Loss.Summary.Boot {
		t.Fatal(again)
	}
	if _, e = Check(cfg); e == nil {
		t.Fatal("root exclusion absent")
	}
}

func TestOptionalLossProductFailureAndResume(t *testing.T) {
	cfg, r := adminFixture(t)
	defer r.Close()
	server := optionalProductServer(t, r)
	defer server.Close()
	if r.optionalQueue.Enqueue(evidence.OptionalRecord{}) {
		t.Fatal("invalid admitted")
	}
	candidate := filepath.Join(cfg.DataDir, "reports", optionalLossDir, "loss.pending")
	if e := os.Mkdir(candidate, 0700); e != nil {
		t.Fatal(e)
	}
	r.snapshotOptionalLoss()
	if !r.OptionalHTTPLogs().Loss.PersistFailed {
		t.Fatal("snapshot failure hidden")
	}
	// 保存不明後の再読込みでは、破損した短いseedをpanicへ流さない。
	seedPath := filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed")
	seed, e := readPrivate(seedPath, 32)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(seed)
	if e = os.WriteFile(seedPath, seed[:31], 0600); e != nil {
		t.Fatal(e)
	}
	r.snapshotOptionalLoss()
	if !r.OptionalHTTPLogs().Loss.PersistFailed {
		t.Fatal("damaged signing seed accepted")
	}
	if e = os.WriteFile(seedPath, seed, 0600); e != nil {
		t.Fatal(e)
	}
	// 別の集計領域の障害が投稿所有列を止めない。
	if !r.PostingCapacity().WriteReady {
		t.Fatal("optional failure stopped mandatory writes")
	}
	if e := os.Remove(candidate); e != nil {
		t.Fatal(e)
	}
	r.snapshotOptionalLoss()
	status := r.OptionalHTTPLogs()
	if status.Loss.PersistFailed || status.Loss.Known.Invalid != 1 || status.Loss.Summary.UncleanBoots != 0 {
		t.Fatal("same-process monitor recovery lost counters", status)
	}
}

func TestOptionalLossProductReservationAndMissingActive(t *testing.T) {
	cfg, r := adminFixture(t)
	server := optionalProductServer(t, r)
	r.packResourcesMu.Lock()
	original := r.packSpace
	r.packSpace = func(string) (platform.DiskSpace, error) { return platform.DiskSpace{Total: 2 << 30, Available: 1}, nil }
	r.packResourcesMu.Unlock()
	r.snapshotOptionalLoss()
	if !r.OptionalHTTPLogs().Loss.PersistFailed {
		t.Fatal("capacity refusal hidden")
	}
	r.packResourcesMu.Lock()
	r.packSpace = original
	r.packResourcesMu.Unlock()
	r.snapshotOptionalLoss()
	if r.OptionalHTTPLogs().Loss.PersistFailed {
		t.Fatal("capacity recovery failed")
	}
	server.Close()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	root := filepath.Join(cfg.DataDir, "reports", optionalLossDir)
	if e := os.Remove(filepath.Join(root, evidence.OptionalLossFile)); e != nil {
		t.Fatal(e)
	}
	if _, e := Check(cfg); e == nil {
		t.Fatal("check accepted missing active history")
	}
	if r, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
		r.Close()
		t.Fatal("active loss history recreated")
	}
	if entries, e := os.ReadDir(root); e != nil || len(entries) != 0 {
		t.Fatal("missing history replaced", entries, e)
	}
}

func TestOptionalLossActivationResume(t *testing.T) {
	cfg, r := adminFixture(t)
	// HTTPを通常起動した後、集計の作成intentへ切り戻す試験ではなく、初回intentを直接保存する。
	r.mu.Lock()
	var ss siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &ss); e != nil {
		t.Fatal(e)
	}
	ss.MinimumReader = 40
	httpActivation := optionalLogActivation{Schema: "optional-http-activation-v1", Site: ss.ID, Phase: "preparing"}
	lossActivation := optionalLogActivation{Schema: "optional-http-loss-activation-v1", Site: ss.ID, Phase: "preparing"}
	e := appendControl(r.site, "test_optional_prepare", []store.Mutation{mutation("site", "state", ss, nil), mutation("optional_http", "http", httpActivation, nil), mutation("optional_loss", "http", lossActivation, nil)}, []string{})
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Mkdir(filepath.Join(cfg.DataDir, "reports", "http"), 0700); e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(cfg); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("check completed pending loss activation", e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if !reopened.OptionalHTTPLogs().Loss.HasSnapshot {
		t.Fatal("pending activation not resumed")
	}
}

func TestOptionalLossShutdownFailureIsUnconfirmed(t *testing.T) {
	cfg, r := adminFixture(t)
	server := optionalProductServer(t, r)
	server.Close()
	r.packResourcesMu.Lock()
	r.packSpace = func(string) (platform.DiskSpace, error) { return platform.DiskSpace{Total: 2 << 30, Available: 1}, nil }
	r.packResourcesMu.Unlock()
	if e := r.Close(); !errors.Is(e, ErrOptionalLossPersistence) {
		t.Fatal("shutdown persistence failure hidden", e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	if got := reopened.OptionalHTTPLogs().Loss.Summary.UncleanBoots; got != 1 {
		t.Fatal("unknown shutdown missing", got)
	}
}

func TestOptionalLossMaintenanceShutdownLockOrder(t *testing.T) {
	_, r := adminFixture(t)
	server := optionalProductServer(t, r)
	server.Close()
	r.optionalCancel()
	<-r.optionalDone
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	r.optionalCancel = cancel
	r.optionalDone = done
	go r.runOptionalLogMaintenance(ctx, r.optionalStore, ticks, done)
	// 巡回がr.mu取得を待っている状態で終了する。待機中のmu解放がないと循環待ちになる。
	r.mu.Lock()
	ticks <- time.Now()
	closed := make(chan error, 1)
	go func() { e := r.closeOptionalLogs(); r.mu.Unlock(); closed <- e }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("maintenance and shutdown lock cycle")
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalLossSnapshotDoesNotHoldPostingOwner(t *testing.T) {
	_, r := adminFixture(t)
	b, e := r.CreateBoard(context.Background(), "losssync", "集計同期中の投稿")
	if e != nil {
		t.Fatal(e)
	}
	public := optionalProductServer(t, r)
	defer public.Close()
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.optionalLossMu.Lock()
	r.optionalLossBeforeSnapshot = func() { close(started); <-release }
	r.optionalLossMu.Unlock()
	go func() { r.snapshotOptionalLoss(); close(finished) }()
	<-started
	form := formServer(t, r, siteID(r.site.State()), b.ID)
	defer form.Close()
	result := make(chan bool, 1)
	go func() {
		v, e := sendForm(form, url.Values{"bbs": {"losssync"}, "subject": {"署名同期とは独立"}, "MESSAGE": {"PRIVATE_REQUIRED_POST"}, "oimo_request_id": {"loss-snapshot-post-01"}})
		result <- e == nil && v.Accepted
	}()
	select {
	case accepted := <-result:
		if !accepted {
			t.Error("posting failed while loss snapshot paused")
		}
	case <-time.After(3 * time.Second):
		t.Error("loss snapshot held required posting owner")
	}
	close(release)
	<-finished
	r.optionalLossMu.Lock()
	r.optionalLossBeforeSnapshot = nil
	r.optionalLossMu.Unlock()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalLossReservationPreservesLastPostingSlot(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	original := r.packSpace
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: (1 << 30) + postingReservationBytes}, nil
	}
	if _, e := r.reservePrivateLossBytes(16 << 10); !errors.Is(e, ErrPostingCapacity) {
		t.Fatal("last posting slot consumed", e)
	}
	release, e := r.reservePosting()
	if e != nil {
		t.Fatal("last required posting reservation rejected", e)
	}
	release()
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: 1 << 20}, nil
	}
	release, e = r.reservePrivateLossBytes(16 << 10)
	if e != nil {
		t.Fatal("minimal status space below posting floor rejected", e)
	}
	release()
	r.packSpace = original
	if r.postReserved != 0 {
		t.Fatal("status reservation leaked")
	}
}
