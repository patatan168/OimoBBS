// 永続作成intentから同一初期frameを再構築し、未完成controlだけを補完する。
package store

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"

	"oimobbs/internal/domain"
)

// CompleteControlCreation はcurrent設置前の初期保存を同じbyte列で完了する。
// 呼出元はdurableな作成intentと排他を必要とする。既存prefix不一致は書換えず拒否する。
func CompleteControlCreation(dir string, h Header, prepared []byte, validate ValueValidator) (*ControlLog, error) {
	if _, err := os.Lstat(dir); os.IsNotExist(err) {
		return CreateControl(dir, h, prepared, validate)
	} else if err != nil {
		return nil, err
	}
	if err := privateRegular(dir, true); err != nil {
		return nil, err
	}
	hb, err := EncodeHeader(h)
	if err != nil || h.Kind == 0 || h.Generation != 1 || h.BaseSeq != 0 {
		return nil, ErrCorrupt
	}
	frame, n, err := ReadFrame(bytes.NewReader(prepared))
	if err != nil || n != int64(len(prepared)) {
		return nil, ErrCorrupt
	}
	if _, err = ApplyControl(ControlState{}, h.Kind, frame, validate); err != nil {
		return nil, err
	}
	stored, err := EncodeWALBlock([][]byte{prepared})
	if err != nil {
		return nil, err
	}
	raw := append(hb, stored...)
	current := filepath.Join(dir, "control.current")
	if _, err = os.Lstat(current); err == nil {
		path := filepath.Join(dir, "control-000001.wal")
		if err = privateRegular(path, false); err != nil {
			return nil, err
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		got, readErr := io.ReadAll(io.LimitReader(f, int64(len(raw))))
		closeErr := f.Close()
		if err = errors.Join(readErr, closeErr); err != nil {
			return nil, err
		}
		if !bytes.Equal(got, raw) {
			return nil, ErrCorrupt
		}
		return OpenControl(dir, h.Kind, h.Owner, h.Key, validate)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.Name() != "control-000001.wal" {
			return nil, errors.New("unexpected incomplete control entry")
		}
	}
	if err = completePrefix(filepath.Join(dir, "control-000001.wal"), raw); err != nil {
		return nil, err
	}
	if err = SyncDirectory(dir); err != nil {
		return nil, err
	}
	m := ControlManifest{Schema: 1, Kind: h.Kind, Owner: h.Owner, Subkey: domain.U64(h.Key), Generation: 1, Delta: Delta{File: "control-000001.wal", RequiredSeq: 1, RequiredEnd: domain.U64(len(raw)), RequiredSHA: sha256.Sum256(raw)}}
	encoded, err := encodeControlCurrent(m)
	if err != nil {
		return nil, err
	}
	if err = atomicFile(dir, "control.current", encoded); err != nil {
		return nil, err
	}
	if err = SyncDirectory(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	return OpenControl(dir, h.Kind, h.Owner, h.Key, validate)
}
func completePrefix(path string, want []byte) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if os.IsExist(err) {
		if err = privateRegular(path, false); err != nil {
			return err
		}
		f, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	got, err := io.ReadAll(io.LimitReader(f, int64(len(want))+1))
	if err != nil {
		return err
	}
	if len(got) > len(want) || !bytes.Equal(got, want[:min(len(got), len(want))]) {
		return ErrCorrupt
	}
	if err = writeFull(f, want[len(got):]); err != nil {
		return err
	}
	return f.Sync()
}
