// 出力名ごとの排他で、強制終了後の一時fileを稼働中の別処理から区別する。
package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// outputPrefix は同じ親directory内の出力名を固定長へ束ね、一時fileとlockの名前に使う。
func outputPrefix(path string) string {
	return fmt.Sprintf(".oimoseal-%x-", sha256.Sum256([]byte(filepath.Base(path))))
}

// lockOutput は既存lockを削除せず、同名出力の処理だけを非待機で排他する。
// lockは0600の空fileとして残し、process終了時にはOSが排他を解放する。
func lockOutput(path string) (*os.File, error) {
	name := filepath.Join(filepath.Dir(path), outputPrefix(path)+"lock")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	if err := validateOutputLock(f); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

// validateOutputLock は他者所有・リンク・権限違いのlockを使わない。
func validateOutputLock(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 0 {
		return errors.New("output lock requires owned regular 0600 empty file")
	}
	return nil
}

// discardOutputPartials は同名出力の排他下でのみ呼び、旧processの一時fileだけを回収する。
func discardOutputPartials(path string) error {
	partials, err := filepath.Glob(filepath.Join(filepath.Dir(path), outputPrefix(path)+"*.partial"))
	if err != nil {
		return err
	}
	for _, partial := range partials {
		if err := validateOutputPartial(partial); err != nil {
			return err
		}
		if err := os.Remove(partial); err != nil {
			return err
		}
	}
	if len(partials) != 0 {
		return syncOutputDirectory(filepath.Dir(path))
	}
	return nil
}

// validateOutputPartial は所有者限定の通常fileだけを中断出力として扱う。link設置後の別名も許す。
func validateOutputPartial(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("unexpected partial output file")
	}
	return nil
}
