// 元予約領域の製品有効化、既知intent補完とactive領域欠落の非再作成を実fileで検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"oimobbs/internal/platform"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func optionalHoldProductFixture(t *testing.T) (Config, *Repository) {
	t.Helper()
	cfg, r := adminFixture(t)
	server := optionalProductServer(t, r)
	server.Close()
	if _, e := r.enableStorageReader(context.Background(), 42, "test_optional_hold_enable"); e != nil {
		t.Fatal(e)
	}
	return cfg, r
}

func TestOptionalHoldProductActivationAndRestart(t *testing.T) {
	cfg, r := optionalHoldProductFixture(t)
	if _, exists := r.site.State().Rows["optional_holds:http"]; exists {
		t.Fatal("unrequested reservation storage activated")
	}
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal(e)
	}
	seq := r.site.State().Seq
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil || r.site.State().Seq != seq {
		t.Fatal("activation not idempotent", e)
	}
	var a optionalLogActivation
	if e := strictjson.Decode(r.site.State().Rows["optional_holds:http"].Value, &a); e != nil || a.Phase != "active" {
		t.Fatal(a, e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if report, e := Check(cfg); e != nil || report.MinimumReader < 42 {
		t.Fatal("active reservation check", report, e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("active reservation restart", e)
	}
	if e := reopened.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalHoldProductMissingActiveStorageIsNotRecreated(t *testing.T) {
	for _, missing := range []string{"directory", "index"} {
		t.Run(missing, func(t *testing.T) {
			cfg, r := optionalHoldProductFixture(t)
			if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
				t.Fatal(e)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory)
			if missing == "index" {
				path = filepath.Join(path, evidence.OptionalHoldIndexFile)
			}
			if e := os.RemoveAll(path); e != nil {
				t.Fatal(e)
			}
			if _, e := Check(cfg); !errors.Is(e, store.ErrCorrupt) {
				t.Fatal("active missing storage check", e)
			}
			if reopened, e := OpenPostingRepository(cfg, postcapture.Validate); e == nil {
				reopened.Close()
				t.Fatal("active missing storage restarted")
			}
			if _, e := os.Stat(path); !os.IsNotExist(e) {
				t.Fatal("missing active storage recreated", e)
			}
		})
	}
}

func TestOptionalHoldProductPreparingRecovery(t *testing.T) {
	for _, stage := range []string{"intent", "index-candidate"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r := optionalHoldProductFixture(t)
			a := optionalLogActivation{Schema: optionalHoldActivationSchema, Site: siteID(r.site.State()), Phase: "preparing"}
			r.mu.Lock()
			e := appendControl(r.site, "test_optional_holds_prepare", []store.Mutation{mutation("optional_holds", "http", a, nil)}, []string{})
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			if stage == "index-candidate" {
				if e := r.optionalStore.InitializeOptionalHolds(); e != nil {
					t.Fatal(e)
				}
				path := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile)
				if e := os.Rename(path, path+".pending"); e != nil {
					t.Fatal(e)
				}
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e := Check(cfg); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("read-only completed preparing storage", e)
			}
			reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("preparing restart", e)
			}
			if e := strictjson.Decode(reopened.site.State().Rows["optional_holds:http"].Value, &a); e != nil || a.Phase != "active" {
				t.Fatal(a, e)
			}
			if e := reopened.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e := Check(cfg); e != nil {
				t.Fatal("completed preparing check", e)
			}
		})
	}
}

func TestOptionalHoldProductActiveIndexCandidateRecovery(t *testing.T) {
	cfg, r := optionalHoldProductFixture(t)
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path+".pending", raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Check(cfg); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("read-only recovered active index candidate", e)
	}
	if unchanged, e := os.ReadFile(path + ".pending"); e != nil || string(unchanged) != string(raw) {
		t.Fatal("read-only changed candidate", e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("active candidate restart", e)
	}
	if e := reopened.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path + ".pending"); !os.IsNotExist(e) {
		t.Fatal("equal candidate not recovered", e)
	}
}

func TestOptionalHoldProductPreparationRepairSameOwner(t *testing.T) {
	cfg, r := optionalHoldProductFixture(t)
	root := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory)
	if e := os.Mkdir(root, 0755); e != nil {
		t.Fatal(e)
	}
	if e := r.ensureOptionalHoldStorage(context.Background()); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("invalid private mode accepted", e)
	}
	var a optionalLogActivation
	if e := strictjson.Decode(r.site.State().Rows["optional_holds:http"].Value, &a); e != nil || a.Phase != "preparing" {
		t.Fatal("failed initialization activated", a, e)
	}
	// 試験上の所有者修復。製品が未知file/modeを自動で修正する経路ではない。
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal("same-owner recovery", e)
	}
	if e := strictjson.Decode(r.site.State().Rows["optional_holds:http"].Value, &a); e != nil || a.Phase != "active" {
		t.Fatal(a, e)
	}
}

func TestOptionalHoldProductPreparationDoesNotHoldCaseMutex(t *testing.T) {
	_, r := optionalHoldProductFixture(t)
	entered, proceed := make(chan struct{}), make(chan struct{})
	r.mu.Lock()
	r.optionalHoldBeforeInitialize = func() { close(entered); <-proceed }
	r.mu.Unlock()
	result := make(chan error, 1)
	go func() { result <- r.ensureOptionalHoldStorage(context.Background()) }()
	<-entered
	// 初期化を止めている間に案件/権限所有mutexを取得できることを、明示channelで確認する。
	locked := make(chan struct{})
	go func() { r.mu.Lock(); close(locked); r.mu.Unlock() }()
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		close(proceed)
		<-result
		t.Fatal("case mutex held while waiting for source initialization")
	}
	close(proceed)
	if e := <-result; e != nil {
		t.Fatal(e)
	}
}

func TestOptionalHoldProductCancelledPreparationAndCapacity(t *testing.T) {
	cfg, r := optionalHoldProductFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := r.ensureOptionalHoldStorage(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, exists := r.site.State().Rows["optional_holds:http"]; exists {
		t.Fatal("canceled request created intent")
	}
	r.packResourcesMu.Lock()
	original := r.packSpace
	originalClock := r.capacityClock
	capacityNow := time.Now()
	r.capacityClock = func() time.Time { return capacityNow }
	r.packSpace = func(string) (platform.DiskSpace, error) { return platform.DiskSpace{Total: 2 << 30, Available: 1}, nil }
	r.packResourcesMu.Unlock()
	if e := r.ensureOptionalHoldStorage(context.Background()); !errors.Is(e, ErrPostingCapacity) {
		t.Fatal("last posting space consumed", e)
	}
	if _, exists := r.site.State().Rows["optional_holds:http"]; exists {
		t.Fatal("capacity refusal created intent")
	}
	r.packResourcesMu.Lock()
	r.packSpace = original
	for i := 0; i < 7; i++ {
		capacityNow = capacityNow.Add(5 * time.Second)
		r.observePostingCapacity()
	}
	r.capacityClock = originalClock
	r.packResourcesMu.Unlock()
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.packResourcesMu.Lock()
	reserved := r.postReserved
	r.packResourcesMu.Unlock()
	if reserved != 0 {
		t.Fatal("initialization reservation leaked", reserved)
	}
	if _, e := os.Stat(filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile)); e != nil {
		t.Fatal(e)
	}
}

func TestOptionalHoldProductPreparationAllowsMandatoryPosting(t *testing.T) {
	_, r := optionalHoldProductFixture(t)
	board, e := r.CreateBoard(context.Background(), "holdsync", "予約初期化中の投稿")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	defer form.Close()
	entered, proceed := make(chan struct{}), make(chan struct{})
	r.mu.Lock()
	r.optionalHoldBeforeInitialize = func() { close(entered); <-proceed }
	r.mu.Unlock()
	initialized := make(chan error, 1)
	go func() { initialized <- r.ensureOptionalHoldStorage(context.Background()) }()
	<-entered
	accepted := make(chan bool, 1)
	go func() {
		result, e := sendForm(form, url.Values{"bbs": {"holdsync"}, "subject": {"初期化との分離"}, "MESSAGE": {"PRIVATE_REQUIRED_POST"}, "oimo_request_id": {"hold-initialize-post-01"}})
		accepted <- e == nil && result.Accepted
	}()
	select {
	case ok := <-accepted:
		if !ok {
			t.Error("posting failed while source initialization paused")
		}
	case <-time.After(5 * time.Second):
		t.Error("source initialization blocked mandatory posting")
	}
	close(proceed)
	if e := <-initialized; e != nil {
		t.Fatal(e)
	}
}

func TestOptionalHoldProductActiveSnapshot(t *testing.T) {
	cfg, r := optionalHoldProductFixture(t)
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	header := r.site.HistoryHeader()
	header.Generation++
	header.BaseSeq = uint64(r.site.State().Seq)
	raw, e := store.EncodeControlSnapshot(header, r.site.State(), 6, snapshotSiteValue)
	r.mu.Unlock()
	if e != nil {
		t.Fatal("active reservation snapshot encode", e)
	}
	state, e := store.DecodeControlSnapshot(raw, header, snapshotSiteValue)
	if e != nil {
		t.Fatal("active reservation snapshot decode", e)
	}
	if _, e := inspectSiteState(state, siteID(state), cfg.Public.BaseURL); e != nil {
		t.Fatal("active reservation snapshot site validation", e)
	}
	var activation optionalLogActivation
	if e := strictjson.Decode(state.Rows["optional_holds:http"].Value, &activation); e != nil || activation.Phase != "active" {
		t.Fatal("active reservation lost in snapshot", activation, e)
	}
}

func TestOptionalHoldProductRequiresActiveHTTPParent(t *testing.T) {
	cfg, r := optionalHoldProductFixture(t)
	if e := r.ensureOptionalHoldStorage(context.Background()); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	state := r.site.State()
	r.mu.Unlock()
	state.Rows = maps.Clone(state.Rows)
	row := state.Rows["optional_http:http"]
	var parent optionalLogActivation
	if e := strictjson.Decode(row.Value, &parent); e != nil {
		t.Fatal(e)
	}
	parent.Phase = "preparing"
	raw, e := json.Marshal(parent)
	if e != nil {
		t.Fatal(e)
	}
	row.Value = raw
	state.Rows["optional_http:http"] = row
	if _, e := inspectSiteState(state, siteID(state), cfg.Public.BaseURL); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("hold storage with incomplete HTTP parent accepted", e)
	}
}
