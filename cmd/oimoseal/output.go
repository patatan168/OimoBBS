// 認証・同期・Closeが完了した出力だけを最終名へ排他的に設置する。
package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
)

// outputFile は実ファイルと同じ境界で書込・同期・Close障害を検査する。
type outputFile interface {
	io.Writer
	Name() string
	Sync() error
	Close() error
}

// newFile は所有者限定の一時fileを完成させてから、既存出力を置換せず最終名へ設置する。
// 最終名の設置後のdirectory同期失敗では、完全な出力を保持したままエラーを返す。
func newFile(path string, write func(io.Writer) error) error {
	return installNewFile(path, write, func(parent string) (outputFile, error) {
		return os.CreateTemp(parent, outputPrefix(path)+"*.partial")
	}, syncOutputDirectory)
}

// installNewFile は変換・Sync・Close・排他的な名前設置・親同期の順序を維持する。
// createとsyncDirは保存障害を検査するための境界で、通常は実OS操作を使う。
func installNewFile(path string, write func(io.Writer) error, create func(string) (outputFile, error), syncDir func(string) error) (err error) {
	lock, err := lockOutput(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	if err := discardOutputPartials(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return &os.PathError{Op: "create", Path: path, Err: os.ErrExist}
	} else if !os.IsNotExist(err) {
		return err
	}
	parent := filepath.Dir(path)
	f, err := create(parent)
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	err = write(f)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	// Linkは同名が先に作られた場合も置換しない。参照される内容は既に認証・同期済み。
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return syncDir(parent)
}

// syncOutputDirectory は最終名の作成と一時名の除去を同期し、Close失敗も返す。
func syncOutputDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
