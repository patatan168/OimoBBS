// Linux上で二重writerが排他取得できないことを確認する。
package platform

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestExclusive(t *testing.T) {
	dir := t.TempDir()
	f, e := Lock(dir)
	if e != nil {
		t.Fatal(e)
	}
	if g, e := Lock(dir); e == nil {
		_ = Unlock(g)
		t.Fatal("second lock succeeded")
	}
	if e = Unlock(f); e != nil {
		t.Fatal(e)
	}
	g, e := Lock(dir)
	if e != nil {
		t.Fatal(e)
	}
	_ = Unlock(g)
}

// 不正なロックfileで待ち続けたり、別名を通じて排他境界を分割したりしない。
func TestLockFileType(t *testing.T) {
	for _, kind := range []string{"fifo", "symlink", "public", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".lock")
			switch kind {
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "target"), path); err != nil {
					t.Fatal(err)
				}
			case "public":
				if err := os.WriteFile(path, nil, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				target := filepath.Join(dir, "target")
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			}
			if f, err := Lock(dir); err == nil {
				_ = Unlock(f)
				t.Fatal("invalid lock accepted")
			}
		})
	}
}
