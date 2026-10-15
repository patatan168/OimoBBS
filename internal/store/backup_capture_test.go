// バックアップ用currentが、捕捉した全確定追記を必須prefixへ固定することを検証する。
package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestThreadBackupCapture(t *testing.T) {
	dir := privateTemp(t)
	owner, frame := fixtureCreate(t)
	thread, err := CreateThread(dir, owner, 1700000000, frame)
	if err != nil {
		t.Fatal(err)
	}
	defer thread.Close()
	cut, err := thread.BackupCapture(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	current, err := DecodeCurrent(cut.Current)
	if err != nil || current.Delta.RequiredSeq != cut.Sequence || current.Delta.RequiredEnd != cut.RequiredEnd || cut.Expires != thread.State().Expires {
		t.Fatal(current, cut, err)
	}
	if len(cut.Files) != 1 || cut.Files[0].Length != cut.RequiredEnd {
		t.Fatal(cut)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "1700000000", cut.Files[0].Name))
	if err != nil || uint64(len(raw)) != uint64(cut.RequiredEnd) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = thread.BackupCapture(ctx); err == nil {
		t.Fatal("cancelled capture accepted")
	}
}
