// 所有者限定の保存先を検査し、同期と非待機排他を共通化する。
package sealedbackup

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"syscall"
)

type durableFile interface {
	io.Writer
	Sync() error
	Close() error
}

func privateInfo(info os.FileInfo, dir bool) error {
	owner, ok := info.Sys().(*syscall.Stat_t)
	mode := os.FileMode(0600)
	if dir {
		mode = 0700
	}
	if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != mode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || dir && !info.IsDir() || !dir && (!info.Mode().IsRegular() || owner.Nlink != 1) {
		return errors.New("backup requires owned private regular file or directory")
	}
	return nil
}
func checkPrivate(path string, dir bool) (os.FileInfo, error) {
	i, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	return i, privateInfo(i, dir)
}

// openPrivate はリンクを辿らず、開く前後の所有者と実体を照合する。
func openPrivate(path string) (*os.File, error) {
	before, e := checkPrivate(path, false)
	if e != nil {
		return nil, e
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, e
	}
	after, e := f.Stat()
	if e == nil {
		e = privateInfo(after, false)
	}
	if e == nil && !os.SameFile(before, after) {
		e = errors.New("backup changed while opening")
	}
	if e != nil {
		return nil, errors.Join(e, f.Close())
	}
	return f, nil
}

// openNewFile は既存ファイルを置換せず、所有者限定の新規ファイルだけを作る。
func openNewFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
}

// syncDirectory は名前の変更とCloseを確認し、両方の失敗を保持する。
func syncDirectory(path string) error {
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	return errors.Join(f.Sync(), f.Close())
}

// lockDirectory は検査済みの固定ファイルで非待機排他を取り、Closeで解放する。
func lockDirectory(root, name string) (*os.File, error) {
	if !filepath.IsAbs(root) {
		return nil, errors.New("absolute backup directory required")
	}
	if _, e := checkPrivate(root, true); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(root, name), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	info, e := f.Stat()
	if e == nil {
		e = privateInfo(info, false)
	}
	if e == nil && info.Size() != 0 {
		e = errors.New("invalid backup lock")
	}
	if e == nil {
		e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	}
	if e != nil {
		return nil, errors.Join(e, f.Close())
	}
	return f, nil
}

// LoadManifest は有界の固定JSONと所有者・権限を検査する。
func LoadManifest(path string) (m Manifest, err error) {
	f, e := openPrivate(path)
	if e != nil {
		return m, e
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	raw, e := io.ReadAll(io.LimitReader(f, metadataLimit+1))
	if e != nil {
		return m, e
	}
	if e = strictjson.DecodeLimit(raw, &m, metadataLimit); e != nil {
		return m, e
	}
	return m, m.Validate()
}
func marshalManifest(m Manifest) ([]byte, error) {
	raw, e := json.Marshal(m)
	return append(raw, '\n'), e
}

// writeDurable は成功した書込だけを同期し、Close失敗も呼出元へ返す。
func writeDurable(f durableFile, write func(io.Writer) error) error {
	e := write(f)
	if e == nil {
		e = f.Sync()
	}
	return errors.Join(e, f.Close())
}
func writeBytes(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}

// fileDigest は所有者限定ファイルの全体hashと長さを有界メモリで求める。
func fileDigest(path string, sync bool) (digest string, size int64, err error) {
	f, e := openPrivate(path)
	if e != nil {
		return "", 0, e
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	h := sha256.New()
	size, e = io.CopyBuffer(h, f, make([]byte, 256<<10))
	if e != nil {
		return "", size, e
	}
	if sync {
		e = f.Sync()
	}
	return fmt.Sprintf("%x", h.Sum(nil)), size, e
}
