// 案件延長と周期原本回収の排他、元期限未反映時の回収停止を検査する。
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"oimobbs/internal/evidence"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

func TestOptionalLiveSweepRejectsUnreflectedCaseExtension(t *testing.T) {
	_, r, c, _, _ := optionalHeldCaseProductFixture(t)
	original, found, e := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e != nil || !found {
		t.Fatal(found, e)
	}
	r.mu.Lock()
	extended, e := r.evidenceCases.Extend(c.ID, c.Creator, c.ETag(), "live-extend", "期限延長", c.Until+domain.Time(24*time.Hour), time.Now())
	r.mu.Unlock()
	if e != nil || extended.Until <= c.Until {
		t.Fatal(extended, e)
	}
	r.sweepOptionalLogs(r.optionalStore)
	if !r.optionalCleanupFailed.Load() {
		t.Fatal("unreflected extension allowed GC")
	}
	after, found, e := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e != nil || !found || after.SHA != original.SHA {
		t.Fatal("source lease changed", after, e)
	}
	rows, e := r.optionalStore.QueryOptionalHold(context.Background(), c.ID, time.Now())
	if e != nil || len(rows) != 1 {
		t.Fatal("original lost", rows, e)
	}
}

func TestEvidenceExtensionLifecycleWaitReleasesCaseMutex(t *testing.T) {
	r := &Repository{}
	r.optionalHoldLifecycleMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest("POST", "/", nil).WithContext(ctx)
	entered := make(chan struct{})
	finished := make(chan error, 1)
	go func() {
		r.mu.Lock()
		close(entered)
		_, e := r.extendEvidenceCase(request, adminauth.Session{}, disclosure.Case{}, "", "", "", 0)
		r.mu.Unlock()
		finished <- e
	}()
	<-entered
	available := make(chan struct{})
	go func() { r.mu.Lock(); r.mu.Unlock(); close(available) }()
	select {
	case <-available:
	case <-time.After(5 * time.Second):
		r.optionalHoldLifecycleMu.Unlock()
		t.Fatal("case mutex held during lifecycle wait")
	}
	select {
	case e := <-finished:
		r.optionalHoldLifecycleMu.Unlock()
		t.Fatal("extension skipped lifecycle gate", e)
	default:
	}
	r.optionalHoldLifecycleMu.Unlock()
	select {
	case e := <-finished:
		if !errors.Is(e, context.Canceled) {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("extension did not resume")
	}
}

func TestOptionalInitializationCloseDuringLifecycleWait(t *testing.T) {
	_, r := adminFixture(t)
	r.optionalHoldLifecycleMu.Lock()
	gateHeld := true
	defer func() {
		if gateHeld {
			r.optionalHoldLifecycleMu.Unlock()
		}
	}()
	entered := make(chan struct{})
	initialized := make(chan error, 1)
	go func() { r.mu.Lock(); close(entered); e := r.ensureOptionalLogs(); r.mu.Unlock(); initialized <- e }()
	<-entered
	state := make(chan bool, 1)
	go func() {
		r.mu.Lock()
		ready := r.optionalQueue != nil && r.optionalCancel != nil && r.optionalDone != nil
		r.mu.Unlock()
		state <- ready
	}()
	select {
	case ready := <-state:
		if !ready {
			t.Fatal("published queue without close lifecycle")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initialization held case mutex during GC wait")
	}
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case e := <-closed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close waited for initializing GC")
	}
	r.optionalHoldLifecycleMu.Unlock()
	gateHeld = false
	select {
	case e := <-initialized:
		if e == nil {
			t.Fatal("closed initialization returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("initialization failed to return after close")
	}
}

// 未接続reader44形式を旧製品readerが受け入れて原本回収へ進まないことを検査する。
func TestExtensionIntentProductReaderFence(t *testing.T) {
	cfg, r, c, _, _ := optionalHeldCaseProductFixture(t)
	r.mu.Lock()
	_, e := r.evidenceCases.PrepareExtension(c.ID, c.Creator, c.ETag(), "reader-fence-extension", "延長", c.Until+domain.Time(24*time.Hour), time.Now())
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(cfg.DataDir, "reports", "http", evidence.OptionalHoldsDirectory, c.ID.String()+".json")
	before, e := os.ReadFile(file)
	if e != nil {
		t.Fatal(e)
	}
	lock, e := platform.Lock(cfg.DataDir)
	if e != nil {
		t.Fatal(e)
	}
	_, checkError := checkLockedPosting(cfg, false, true)
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	if checkError == nil {
		t.Fatal("old reader check accepted extension intent")
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e == nil {
		reopened.Close()
		t.Fatal("old reader startup accepted extension intent")
	}
	after, e := os.ReadFile(file)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("old reader changed source", e)
	}
}
