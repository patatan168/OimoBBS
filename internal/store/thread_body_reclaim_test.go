// 未知・改変・symlinkの保存先を保持し、既知ファイルの途中回収だけを再開する。
package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReclaimedBodyProtectsUnknownFiles(t *testing.T) {
	for _, kind := range []string{"unknown", "changed", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			owner, frame := fixtureCreate(t)
			parent := privateTemp(t)
			log, e := CreateThread(parent, owner, 1, frame)
			if e != nil {
				t.Fatal(e)
			}
			files, e := log.BodySourceFiles(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if e = log.Close(); e != nil {
				t.Fatal(e)
			}
			dir := filepath.Join(parent, "1")
			target := filepath.Join(dir, "delta-000001.wal")
			switch kind {
			case "unknown":
				e = os.WriteFile(filepath.Join(dir, "unknown"), []byte("keep"), 0600)
			case "changed":
				e = os.WriteFile(target, []byte("keep"), 0600)
			case "symlink":
				if e = os.Remove(target); e == nil {
					e = os.Symlink(filepath.Join(parent, "outside"), target)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = RemoveReclaimedBody(context.Background(), dir, files, nil); e == nil {
				t.Fatal("unsafe source deleted")
			}
			if _, e = os.Lstat(filepath.Join(dir, "current.json")); e != nil {
				t.Fatal("known file removed before full validation", e)
			}
		})
	}
}

func TestReclaimedBodyResumesPartialUnlink(t *testing.T) {
	owner, frame := fixtureCreate(t)
	parent := privateTemp(t)
	log, e := CreateThread(parent, owner, 1, frame)
	if e != nil {
		t.Fatal(e)
	}
	files, e := log.BodySourceFiles(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if e = log.Close(); e != nil {
		t.Fatal(e)
	}
	dir := filepath.Join(parent, "1")
	if e = RemoveReclaimedBody(context.Background(), dir, files, func(string) error { return errors.New("crash") }); e == nil {
		t.Fatal("checkpoint ignored")
	}
	if e = RemoveReclaimedBody(context.Background(), dir, files, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Lstat(dir); !os.IsNotExist(e) {
		t.Fatal("body remains", e)
	}
	if e = RemoveReclaimedBody(context.Background(), dir, files, nil); e != nil {
		t.Fatal("idempotent recovery", e)
	}
}
