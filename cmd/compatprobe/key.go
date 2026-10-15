// 試験用管理キーを所有者だけが読めるファイルから読み、初回のみ生成する。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// loadAdminKey は既存キーを保持し、新規ファイルは0600で排他的に作成する。
func loadAdminKey(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		var key [32]byte
		_, _ = rand.Read(key[:])
		value := hex.EncodeToString(key[:])
		_, writeErr := io.WriteString(f, value+"\n")
		syncErr := f.Sync()
		closeErr := f.Close()
		for _, e := range []error{writeErr, syncErr, closeErr} {
			if e != nil {
				return "", e
			}
		}
		return value, nil
	}
	if !os.IsExist(err) {
		return "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return "", fmt.Errorf("admin key must be a regular owner-only file: %s", path)
	}
	f, err = os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", fmt.Errorf("admin key file changed while opening")
	}
	b, err := io.ReadAll(io.LimitReader(f, 66))
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(string(b), "\n")
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("invalid admin key file: %s", path)
	}
	return value, nil
}
