// オンライン捕捉の全体排他・共有容量予約・取消解放と列外コピーを検証する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOnlineBackupResources(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	ctx := context.Background()
	info, e := r.CreateBoard(ctx, "quota", "容量試験")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, r, siteID(r.site.State()), info.ID)
	defer server.Close()
	first, e := sendForm(server, url.Values{"bbs": {"quota"}, "subject": {"copy"}, "MESSAGE": {"first"}, "oimo_request_id": {"quota-first-0001"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	pin, e := r.PinThreadBackup(ctx, info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	if r.PostingCapacity().ReservedBytes != onlineBackupDefaultBytes+onlineBackupOverhead {
		t.Fatal(r.PostingCapacity())
	}
	if _, e := r.PinThreadBackup(ctx, info.ID, first.Key); !errors.Is(e, ErrOnlineBackupBusy) {
		t.Fatal(e)
	}
	if e = pin.Close(); e != nil {
		t.Fatal(e)
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("reservation leaked")
	}
	parent := t.TempDir()
	if e = os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	cut, e := r.CopyThreadBackup(ctx, info.ID, first.Key, filepath.Join(parent, fmt.Sprint(first.Key)), OnlineBackupCopyOptions{})
	if e != nil || cut.Sequence != 1 || r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal(cut, e)
	}
	restored, e := store.OpenThread(parent, info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	restored.Close()
	runCtx, cancel := context.WithCancel(ctx)
	pin, e = r.PinThreadBackup(runCtx, info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	cancel()
	if e = pin.Close(); e != nil {
		t.Fatal(e)
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("cancel release leaked")
	}
	for _, o := range []OnlineBackupCopyOptions{{MaxBytes: 1}, {MaxBytes: 2 << 30}, {Budget: time.Hour}} {
		if _, e = r.CopyThreadBackup(ctx, info.ID, first.Key, filepath.Join(parent, "invalid"), o); e == nil {
			t.Fatal(o)
		}
	}
	// 既存出力を拒否した後も予約と所有者固定は再利用できる。
	if _, e = r.CopyThreadBackup(ctx, info.ID, first.Key, filepath.Join(parent, fmt.Sprint(first.Key)), OnlineBackupCopyOptions{}); e == nil {
		t.Fatal("existing output accepted")
	}
	if r.PostingCapacity().ReservedBytes != 0 {
		t.Fatal("failed copy reservation leaked")
	}
	// 圧縮一件だけなら収まる容量でも、捕捉と同時には受け付けない。
	r.packResourcesMu.Lock()
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 10 << 30, Available: (1 << 30) + max(packReservationBytes, onlineBackupDefaultBytes+onlineBackupOverhead)}, nil
	}
	r.packResourcesMu.Unlock()
	pin, e = r.PinThreadBackup(ctx, info.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.reservePack(); !errors.Is(e, app.ErrPackCapacity) {
		t.Fatal("backup reservation omitted from pack admission", e)
	}
	if e = pin.Close(); e != nil {
		t.Fatal(e)
	}
	packRelease, e := r.reservePack()
	if e != nil {
		t.Fatal("pack admission did not recover", e)
	}
	packRelease()
	r.packResourcesMu.Lock()
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 10 << 30, Available: 1 << 30}, nil
	}
	r.packResourcesMu.Unlock()
	if _, e = r.PinThreadBackup(ctx, info.ID, first.Key); !errors.Is(e, ErrOnlineBackupCapacity) {
		t.Fatal(e)
	}
	if r.backupReserved != 0 {
		t.Fatal("capacity refusal leaked")
	}
}
