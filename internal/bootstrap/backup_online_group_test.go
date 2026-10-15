// 板単位の同時境界捕捉を、実投稿の継続・中断・資源上限とともに検証する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/evidence"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestOnlineBoardBackupGroup(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "group", "一括捕捉")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	first, e := sendForm(server, url.Values{"bbs": {"group"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"group-first-0001"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	pin, e := r.PinBoardBackup(ctx, info.ID, OnlineBackupGroupOptions{})
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	if _, e = r.PinThreadBackup(ctx, info.ID, first.Key); !errors.Is(e, ErrOnlineBackupBusy) {
		t.Fatal(e)
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	type result struct {
		cut OnlineBackupGroupCapture
		err error
	}
	done := make(chan result, 1)
	target := filepath.Join(parent, "board")
	go func() {
		cut, err := pin.copy(ctx, target, func(int) error {
			select {
			case <-started:
			default:
				close(started)
				<-release
			}
			return nil
		})
		done <- result{cut, err}
	}()
	<-started
	reply, e := sendForm(server, url.Values{"bbs": {"group"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"second"}, "oimo_request_id": {"group-reply-0001"}})
	if e != nil || reply.Number != 2 {
		t.Fatal(reply, e)
	}
	second, e := sendForm(server, url.Values{"bbs": {"group"}, "subject": {"new"}, "MESSAGE": {"new"}, "oimo_request_id": {"group-next-00001"}})
	if e != nil || !second.Accepted {
		t.Fatal(second, e)
	}
	close(release)
	got := <-done
	if got.err != nil || len(got.cut.Captures) != 3 || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(got.cut, got.err)
	}
	copied, e := store.OpenThread(filepath.Join(target, "thread", info.ID.String()), info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	if copied.State().Revision != 1 {
		t.Fatal(copied.State())
	}
	copied.Close()
	if _, e = os.Stat(filepath.Join(target, "thread", info.ID.String(), fmt.Sprint(second.Key))); !os.IsNotExist(e) {
		t.Fatal(e)
	}

	// コピーされた証拠署名を再生し、threadとの確定判断照合も通る。
	var journals []*evidence.Journal
	for _, c := range got.cut.Captures {
		if c.Kind == "board" {
			control, err := store.OpenControlWithValidators(filepath.Join(target, c.Kind, c.Owner.String(), c.Subkey), 2, info.ID, 0, validateBoardValue, snapshotBoardValue)
			if err != nil {
				t.Fatal(err)
			}
			if control.State().Seq != c.Capture.Sequence {
				t.Fatal("control cut changed")
			}
			control.Close()
		}
		if c.Kind == "evidence" {
			day, err := strconv.ParseUint(c.Subkey, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			j, err := evidence.OpenJournal(filepath.Join(target, c.Kind, c.Owner.String(), c.Subkey), info.ID, day, 10, r.posting[info.ID].key, app.PostingValidator(r.posting[info.ID].validate))
			if err != nil {
				t.Fatal(err)
			}
			journals = append(journals, j)
		}
	}
	if len(journals) != 1 {
		t.Fatal("missing evidence", len(journals))
	}
	replay, err := app.OpenPosting(filepath.Join(target, "thread", info.ID.String()), info.ID, first.Key, journals, journals[0], domain.Time(time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	if snap := replay.Snapshot(domain.Time(time.Now().UnixNano())); snap == nil || snap.Revision != 1 {
		t.Fatal("posting replay advanced")
	}
	replay.Close()
	for _, j := range journals {
		j.Close()
	}
	if _, e = r.PinBoardBackup(ctx, info.ID, OnlineBackupGroupOptions{MaxOwners: 1}); !errors.Is(e, ErrOnlineBackupOwners) {
		t.Fatal(e)
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("failed admission leaked")
	}
	ctx2, cancel := context.WithCancel(ctx)
	group, e := r.PinBoardBackup(ctx2, info.ID, OnlineBackupGroupOptions{})
	if e != nil {
		t.Fatal(e)
	}
	released := make(chan struct{})
	group.mu.Lock()
	originalRelease := group.release
	group.release = func() { originalRelease(); close(released) }
	group.mu.Unlock()
	cancel()
	select {
	case <-released:
	case <-time.After(3 * time.Second):
		t.Fatal("idle cancellation did not release group")
	}
	if e = group.Close(); e != nil {
		t.Fatal(e)
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("cancel leaked")
	}
	if _, e = r.CopyBoardBackup(ctx, info.ID, target, OnlineBackupGroupOptions{}); e == nil {
		t.Fatal("overwrote output")
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("copy failure leaked")
	}
	if _, e = r.CopyBoardBackup(ctx, info.ID, filepath.Join(parent, "fresh"), OnlineBackupGroupOptions{}); e != nil {
		t.Fatal(e)
	}
	site, e := r.PinSiteBackup(ctx, OnlineBackupCopyOptions{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.PinBoardBackup(ctx, info.ID, OnlineBackupGroupOptions{}); !errors.Is(e, ErrOnlineBackupBusy) {
		t.Fatal(e)
	}

	if _, e = r.CreateBoard(ctx, "afterpin", "サイト捕捉後"); e != nil {
		t.Fatal(e)
	}
	siteParent := t.TempDir()
	if e = os.Chmod(siteParent, 0700); e != nil {
		t.Fatal(e)
	}
	siteCut, e := site.Copy(ctx, filepath.Join(siteParent, "control"))
	if e != nil {
		t.Fatal(e)
	}
	restoredSite, e := store.OpenControlWithValidators(filepath.Join(siteParent, "control"), 1, siteID(r.site.State()), 0, validateSiteValue, snapshotSiteValue)
	if e != nil {
		t.Fatal(e)
	}
	if restoredSite.State().Seq != siteCut.Sequence {
		t.Fatal("site cut changed")
	}

	if siteCut.Sequence >= r.site.State().Seq {
		t.Fatal("site did not retain old prefix")
	}
	restoredSite.Close()
	if _, e = r.CopySiteBackup(ctx, filepath.Join(siteParent, "second"), OnlineBackupCopyOptions{}); e != nil {
		t.Fatal(e)
	}

	if _, e = r.PinBoardBackup(ctx, domain.NewID(), OnlineBackupGroupOptions{}); e == nil {
		t.Fatal("unknown board")
	}
}

func TestOnlineBackupGroupFailures(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "errors", "失敗捕捉")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	first, e := sendForm(server, url.Values{"bbs": {"errors"}, "subject": {"first"}, "MESSAGE": {"first"}, "oimo_request_id": {"group-error-0001"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	b := r.posting[info.ID]
	_, e = b.worker.SubmitIdle(ctx, func() (any, error) {
		pin, err := b.control.PinBackup(ctx)
		if err != nil {
			return nil, err
		}
		limit := pin.ReferenceBytes() + 1
		pin.Close()
		life, cancel := context.WithCancel(ctx)
		g := &OnlineBackupGroup{lifetime: life, cancel: cancel}
		err = b.pinBackupGroup(g, OnlineBackupGroupOptions{MaxBytes: limit, MaxOwners: 64})
		if !errors.Is(err, store.ErrBackupPinBudget) || len(g.parts) != 1 {
			g.Close()
			return nil, fmt.Errorf("partial budget guard failed: %v", err)
		}
		return nil, g.Close()
	})
	if e != nil {
		t.Fatal(e)
	}

	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := b.worker.Submit(ctx, func() (any, error) { close(started); <-release; return nil, nil })
		done <- err
	}()
	<-started
	_, busyErr := r.PinBoardBackup(ctx, info.ID, OnlineBackupGroupOptions{})
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(busyErr, board.ErrBusy) || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(busyErr)
	}
	_, e = b.worker.Submit(ctx, func() (any, error) {
		snap := b.threads[first.Key].Snapshot(domain.Time(time.Now().UnixNano()))
		b.clock = func() time.Time { return time.Unix(0, int64(snap.Expires)+1) }
		return nil, nil
	})
	if e != nil {
		t.Fatal(e)
	}
	_, expiredErr := r.PinBoardBackup(ctx, info.ID, OnlineBackupGroupOptions{})
	_, e = b.worker.Submit(ctx, func() (any, error) { b.clock = time.Now; return nil, nil })
	if e != nil || expiredErr == nil || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(e, expiredErr)
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	g, e := r.PinBoardBackup(ctx, info.ID, OnlineBackupGroupOptions{})
	if e != nil {
		t.Fatal(e)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	target := filepath.Join(parent, "partial")
	cut, e := g.copy(cancelCtx, target, func(i int) error {
		if i == 1 {
			cancel()
		}
		return nil
	})
	if !errors.Is(e, context.Canceled) || len(cut.Captures) != 0 || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(cut, e)
	}
	if _, e = os.Stat(filepath.Join(target, "board", info.ID.String(), "control", "control.current")); e != nil {
		t.Fatal("first completed component not retained", e)
	}
	for _, o := range []OnlineBackupGroupOptions{{MaxOwners: -1}, {MaxOwners: 257}, {MaxBytes: 1}, {Budget: time.Hour}} {
		if _, e = r.PinBoardBackup(ctx, info.ID, o); e == nil {
			t.Fatal(o)
		}
	}
	if _, e = r.CopyBoardBackup(ctx, info.ID, filepath.Join(r.cfg.DataDir, "invalid"), OnlineBackupGroupOptions{}); e == nil {
		t.Fatal("source output accepted")
	}
	if _, e = os.Stat(filepath.Join(r.cfg.DataDir, "invalid")); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if _, e = r.CopyBoardBackup(ctx, info.ID, filepath.Join(parent, "complete"), OnlineBackupGroupOptions{}); e != nil {
		t.Fatal(e)
	}
}
