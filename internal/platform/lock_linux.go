//go:build linux

// Package platform はLinuxのデータ所有排他を隔離する。
package platform

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Lock はデータディレクトリの非待機排他を取得する。二重writerを拒否する。
func Lock(dir string) (*os.File, error) {
	f, e := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if e != nil {
		return nil, e
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 {
		_ = f.Close()
		return nil, errors.New("lock must be a private regular file owned by the service user")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		_ = f.Close()
		return nil, e
	}
	return f, nil
}

// Unlock は排他を解放しfileを閉じる。
func Unlock(f *os.File) error {
	e := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
