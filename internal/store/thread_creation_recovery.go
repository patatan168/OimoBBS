// 署名済み作成要求と完全一致する初回WALから、未設置のcurrentだけを補完する。
package store

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"strings"
)

// RecoverThreadCreation はcurrent未設置の初回保存を完了する。
// 呼出元は排他を保持し、未決定の単一署名済みcreateを検証して渡す。
// WALの不足・余剰・不一致、既存current、他世代は上書きせず拒否する。
func RecoverThreadCreation(parent string, owner domain.ID, key uint64, prepared []byte) error {
	if _, err := ValidateThreadFrame(nil, prepared); err != nil {
		return err
	}
	header, err := EncodeHeader(Header{Owner: owner, Key: key, Generation: 1})
	if err != nil {
		return err
	}
	stored, err := EncodeWALBlock([][]byte{prepared})
	if err != nil {
		return err
	}
	want := append(header, stored...)
	m := Manifest{Schema: 1, BoardID: owner, ThreadKey: domain.U64(key), Generation: 1,
		Delta: Delta{File: "delta-000001.wal", RequiredSeq: 1, RequiredEnd: domain.U64(len(want)), RequiredSHA: sha256.Sum256(want)}}
	current, err := EncodeCurrent(m)
	if err != nil {
		return err
	}
	dir := filepath.Join(parent, fmt.Sprint(key))
	if err = privateRegular(dir, true); err != nil {
		return err
	}
	if _, err = os.Lstat(filepath.Join(dir, "current.json")); !os.IsNotExist(err) {
		return ErrCorrupt
	}
	if err = checkThreadCreationFiles(dir, m.Delta.File, current); err != nil {
		return err
	}
	if err = syncThreadCreationWAL(filepath.Join(dir, m.Delta.File), want); err != nil {
		return err
	}
	if err = SyncDirectory(dir); err != nil {
		return err
	}
	if err = SyncDirectory(parent); err != nil {
		return err
	}
	return InstallCurrent(dir, current)
}

// checkThreadCreationFiles は初回WALと同じcurrentの設置途中byteだけを許す。
func checkThreadCreationFiles(dir, wal string, current []byte) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, readErr := d.Readdirnames(4097)
	closeErr := d.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(names) > 4096 {
		return ErrCorrupt
	}
	for _, name := range names {
		if err = checkThreadCreationFile(dir, name, wal, current); err != nil {
			return err
		}
	}
	return nil
}

// checkThreadCreationFile は未知の保存名と、別内容の設置途中fileを拒否する。
func checkThreadCreationFile(dir, name, wal string, current []byte) error {
	path := filepath.Join(dir, name)
	if err := privateRegular(path, false); err != nil {
		return err
	}
	if name == wal {
		return nil
	}
	if !strings.HasPrefix(name, ".install-") || len(name) <= len(".install-") {
		return ErrCorrupt
	}
	raw, err := readBounded(path, int64(len(current)))
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(current, raw) {
		return ErrCorrupt
	}
	return nil
}

// syncThreadCreationWAL は既存byteの完全一致を確認し、参照設置より前に再同期する。
func syncThreadCreationWAL(path string, want []byte) error {
	if err := privateRegular(path, false); err != nil {
		return err
	}
	raw, err := readBounded(path, int64(len(want)))
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, want) {
		return ErrCorrupt
	}
	// 前processのWrite直後に停止した場合も、参照の設置前にWALを同期する。
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return nil
}
