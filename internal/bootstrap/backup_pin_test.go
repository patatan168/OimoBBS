// 実HTTP投稿の稼働所有列から捕捉し、投稿/圧縮/回収継続後も旧境界を再生する。
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

	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestPostingPinnedBackup(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "pin", "捕捉試験")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	first, e := sendForm(server, url.Values{"bbs": {"pin"}, "subject": {"capture"}, "MESSAGE": {"first"}, "oimo_request_id": {"pin-first-000001"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	if _, e = r.EnablePostingPacks(ctx); e != nil {
		t.Fatal(e)
	}
	pin, e := r.PinThreadBackup(ctx, info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	defer pin.Close()
	reply, e := sendForm(server, url.Values{"bbs": {"pin"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"second"}, "oimo_request_id": {"pin-reply-000001"}})
	if e != nil || reply.Number != 2 {
		t.Fatal(reply, e)
	}
	if _, e = r.CompactThread(ctx, info.ID, first.Key, 6, true); e != nil {
		t.Fatal(e)
	}
	if _, e = r.ReclaimThreadPack(ctx, info.ID, first.Key, true); e != nil {
		t.Fatal(e)
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cut, e := pin.Copy(ctx, filepath.Join(parent, fmt.Sprint(first.Key)))
	if e != nil || cut.Sequence != 1 {
		t.Fatal(cut, e)
	}
	restored, e := store.OpenThread(parent, info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	if restored.State().Revision != 1 {
		t.Fatal(restored.State())
	}
	restored.Close()
	live, e := r.Thread(ctx, info.ID, first.Key)
	if e != nil || live.Revision != 2 {
		t.Fatal(live, e)
	}
	b := r.posting[info.ID]
	started, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, e := b.worker.Submit(ctx, func() (any, error) { close(started); <-release; return nil, nil })
		done <- e
	}()
	<-started
	if _, e = r.PinThreadBackup(ctx, info.ID, first.Key); !errors.Is(e, board.ErrBusy) {
		t.Fatal("busy owner not deferred", e)
	}
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e = r.PinThreadBackup(canceled, info.ID, first.Key); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e = r.PinThreadBackup(ctx, domain.NewID(), first.Key); e == nil {
		t.Fatal("unknown owner")
	}
	if _, e = r.PinThreadBackup(ctx, info.ID, first.Key+1); e == nil {
		t.Fatal("unknown thread")
	}
	if _, e = b.worker.Submit(ctx, func() (any, error) {
		b.clock = func() time.Time { return time.Unix(0, int64(live.Expires)+1) }
		return nil, nil
	}); e != nil {
		t.Fatal(e)
	}
	if _, e = r.PinThreadBackup(ctx, info.ID, first.Key); e == nil {
		t.Fatal("expired thread captured")
	}

}
