// 初期化が扱うディレクトリ・鍵の所有者、権限、リンクとサイズを検査する。
package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"oimobbs/internal/store"
)

// noSymlinks は祖先も含めてsymlinkによる保存領域の迂回を拒否する。
func noSymlinks(path string) error {
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not allowed: %s", p)
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}
func privatePath(path string, directory bool) error {
	if err := noSymlinks(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	want := os.FileMode(0600)
	if directory {
		want = 0700
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != want || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.IsDir() != directory || !directory && (!info.Mode().IsRegular() || st.Nlink != 1) {
		return fmt.Errorf("invalid owner, permissions, or file type: %s", path)
	}
	return nil
}
func readPrivate(path string, max int64) ([]byte, error) {
	if err := privatePath(path, false); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, errors.New("storage file exceeds limit")
	}
	return b, nil
}

// writeNew は既存fileを変更せず、書込とSyncとcloseのすべてが成功した場合だけ戻る。
func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.Write(b)
	if writeErr == nil && n != len(b) {
		writeErr = io.ErrShortWrite
	}
	var syncErr error
	if writeErr == nil {
		syncErr = f.Sync()
	}
	return errors.Join(writeErr, syncErr, f.Close())
}
func makePrivateDir(path string) error {
	if err := os.Mkdir(path, 0700); err != nil {
		return err
	}
	return store.SyncDirectory(filepath.Dir(path))
}
func requireEmpty(dir string) error {
	if err := privatePath(dir, true); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Readdirnames(1)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("unverified data in %s: bootstrap supports an initial site only", dir)
}
