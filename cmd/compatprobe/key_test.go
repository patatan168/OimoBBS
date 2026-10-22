// 管理キーの再起動時の保持と、公開権限・リンク・破損ファイルの拒否を検証する。
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdminKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "admin.key")
	first, err := loadAdminKey(path)
	if err != nil || len(first) != 64 {
		t.Fatalf("create: %v", err)
	}
	second, err := loadAdminKey(path)
	if err != nil || second != first {
		t.Fatalf("reload: %v", err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAdminKey(path); err == nil {
		t.Fatal("readable key accepted")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(filepath.Dir(path), "link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAdminKey(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if err = os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = loadAdminKey(path); err == nil {
		t.Fatal("broken key replaced")
	}
}
