// 一括回収の件数制限、再開、稼働中の延期、不正領域の保持を検証する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

// partialSweepRoot は同じbackupに束縛した本文未複写の作業領域を構成する。
func partialSweepRoot(t *testing.T, parent, name, keys string, p replayCleanupPlan) string {
	t.Helper()
	root := filepath.Join(parent, name)
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	lock, e := platform.Lock(root)
	if e != nil {
		t.Fatal(e)
	}
	defer platform.Unlock(lock)
	if _, e = writeReplayCleanupPlan(root, keys, p.Backup, p.BackupSHA, time.Now()); e != nil {
		t.Fatal(e)
	}
	return root
}

func TestReplaySweepPaginationAndRejection(t *testing.T) {
	backup, keys, existing := staleReplayFixture(t)
	parent := filepath.Dir(existing)
	key, e := replayCleanupKey(keys)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(key[:])
	raw, e := readPrivate(filepath.Join(existing, backupReplayGate), replayCleanupLimit)
	if e != nil {
		t.Fatal(e)
	}
	p, e := decodeReplayCleanupPlan(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	// fixture生成rootを先に回収し、以下の名前順を固定する。
	if _, e = ReclaimBackupReplay(context.Background(), existing, keys, true); e != nil {
		t.Fatal(e)
	}
	a := partialSweepRoot(t, parent, ".backup-replay-a", keys, p)
	b := partialSweepRoot(t, parent, ".backup-replay-b", keys, p)
	c := partialSweepRoot(t, parent, ".backup-replay-c", keys, p)
	if e = os.WriteFile(filepath.Join(c, "unknown"), []byte("retain"), 0600); e != nil {
		t.Fatal(e)
	}
	unrelated := filepath.Join(parent, "notes")
	if e = os.WriteFile(unrelated, []byte("retain"), 0600); e != nil {
		t.Fatal(e)
	}
	lock, e := platform.Lock(b)
	if e != nil {
		t.Fatal(e)
	}
	preview, e := SweepBackupReplay(context.Background(), parent, keys, "", 2, false)
	if e != nil || len(preview.Items) != 2 || preview.Items[0].Status != "verified" || preview.Items[1].Status != "busy" || !preview.More || preview.Next != filepath.Base(b) || preview.Busy != 1 {
		t.Fatal(preview, e)
	}
	if _, e = os.Stat(a); e != nil {
		t.Fatal("preview changed root", e)
	}
	first, e := SweepBackupReplay(context.Background(), parent, keys, "", 2, true)
	if e != nil || first.Items[0].Status != "reclaimed" || first.Items[1].Status != "busy" {
		t.Fatal(first, e)
	}
	next, e := SweepBackupReplay(context.Background(), parent, keys, first.Next, 2, true)
	if !errors.Is(e, ErrReplaySweepRejected) || len(next.Items) != 1 || next.Rejected != 1 || next.More || next.Next != filepath.Base(c) {
		t.Fatal(next, e)
	}
	if e = platform.Unlock(lock); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(c, "unknown")); e != nil {
		t.Fatal("rejected payload removed", e)
	}
	if e = os.Remove(filepath.Join(c, "unknown")); e != nil {
		t.Fatal(e)
	}
	// busy領域はページ末尾からでなく、次の巡回を先頭から始めて再確認する。
	final, e := SweepBackupReplay(context.Background(), parent, keys, "", 128, true)
	if e != nil || len(final.Items) != 2 || final.More || final.RestoreReady {
		t.Fatal(final, e)
	}
	for _, item := range final.Items {
		if item.Status != "reclaimed" {
			t.Fatal(item)
		}
	}
	if _, e = VerifyBackupWithKeys(context.Background(), backup, keys); e != nil {
		t.Fatal("backup changed", e)
	}
	if _, e = os.Stat(unrelated); e != nil {
		t.Fatal("unrelated file removed", e)
	}
	link := filepath.Join(parent, ".backup-replay-link")
	if e = os.Symlink(backup, link); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(parent, ".backup-replay-file")
	if e = os.WriteFile(file, []byte("retain"), 0600); e != nil {
		t.Fatal(e)
	}
	bad := partialSweepRoot(t, parent, ".backup-replay-tampered", keys, p)
	if e = os.WriteFile(filepath.Join(bad, backupReplayGate), []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	rejected, e := SweepBackupReplay(context.Background(), parent, keys, "", 16, true)
	if !errors.Is(e, ErrReplaySweepRejected) || rejected.Rejected != 3 || len(rejected.Items) != 3 {
		t.Fatal(rejected, e)
	}
	for _, path := range []string{link, file, filepath.Join(bad, backupReplayGate)} {
		if _, e = os.Lstat(path); e != nil {
			t.Fatal("unsafe candidate changed", path, e)
		}
	}
	for _, limit := range []int{0, 129} {
		if _, e = SweepBackupReplay(context.Background(), parent, keys, "", limit, true); e == nil {
			t.Fatal("bad limit accepted")
		}
	}
	if _, e = SweepBackupReplay(context.Background(), parent, keys, "../escape", 1, true); e == nil {
		t.Fatal("bad cursor accepted")
	}
	if _, e = SweepBackupReplay(context.Background(), parent, parent, "", 1, true); e == nil {
		t.Fatal("overlap accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = SweepBackupReplay(ctx, parent, keys, "", 1, true); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestReplaySweepEnumerationBound(t *testing.T) {
	parent := t.TempDir()
	for i := 0; i <= replaySweepEntryLimit; i++ {
		if e := os.WriteFile(filepath.Join(parent, fmt.Sprintf("entry-%04d", i)), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := replaySweepNames(context.Background(), parent, ""); e == nil {
		t.Fatal("unbounded parent accepted")
	}
}
