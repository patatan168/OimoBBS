// 中断した受信と期限回収を再開し、元の期限内の完成世代を保持する。
package sealedbackup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// removePairDirectory は既知の二ファイルだけを削除し、未知の内容は保持して拒否する。
func removePairDirectory(path string) error {
	if _, e := checkPrivate(path, true); e != nil {
		return e
	}
	entries, e := os.ReadDir(path)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.Name() != "archive.seal" && entry.Name() != "manifest.json" {
			return errors.New("unexpected file in backup directory")
		}
		if _, e := checkPrivate(filepath.Join(path, entry.Name()), false); e != nil {
			return e
		}
	}
	for _, entry := range entries {
		if e := os.Remove(filepath.Join(path, entry.Name())); e != nil {
			return e
		}
	}
	return os.Remove(path)
}

// Sweep は独立した受信先timerから呼ぶ期限回収。受信中は非待機で拒否する。
func (r *Receiver) Sweep() (removed int, err error) {
	lock, e := lockDirectory(r.root, ".receive.lock")
	if e != nil {
		return 0, e
	}
	defer func() { err = errors.Join(err, lock.Close()) }()
	resumed, e := r.cleanUnfinished()
	if e != nil {
		return resumed, e
	}
	n, e := r.expireGenerations()
	return resumed + n, e
}

// cleanUnfinished は排他下で中断した受信・期限回収を完了させる。
func (r *Receiver) cleanUnfinished() (int, error) {
	entries, e := os.ReadDir(r.root)
	if e != nil {
		return 0, e
	}
	n := 0
	changed := false
	for _, entry := range entries {
		if !unfinishedName.MatchString(entry.Name()) {
			continue
		}
		if e = r.removePair(filepath.Join(r.root, entry.Name())); e != nil {
			return n, e
		}
		changed = true
		if strings.HasPrefix(entry.Name(), ".expired-") {
			n++
		}
	}
	if changed {
		e = r.syncDir(r.root)
	}
	return n, e
}

// expireGenerations は回収名への変更を永続化してから内容を削除する。
func (r *Receiver) expireGenerations() (int, error) {
	entries, e := os.ReadDir(r.root)
	if e != nil {
		return 0, e
	}
	n := 0
	for _, entry := range entries {
		if !generationName.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(r.root, entry.Name())
		if _, e = checkPrivate(path, true); e != nil {
			return n, e
		}
		m, e := LoadManifest(filepath.Join(path, "manifest.json"))
		if e != nil {
			return n, e
		}
		if entry.Name() != m.Generation() {
			return n, errors.New("backup generation mismatch")
		}
		if m.ExpiresAtNS > r.now().UnixNano() {
			continue
		}
		suffix, e := randomSuffix()
		if e != nil {
			return n, e
		}
		retired := filepath.Join(r.root, ".expired-"+entry.Name()+"-"+suffix)
		if e = r.rename(path, retired); e != nil {
			return n, e
		}
		if e = r.syncDir(r.root); e != nil {
			return n, e
		}
		if e = r.removePair(retired); e != nil {
			return n, e
		}
		n++
	}
	if n > 0 {
		e = r.syncDir(r.root)
	}
	return n, e
}
