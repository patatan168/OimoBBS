// currentが指定したsnapshotの所有権・長さ・SHA・全行を検証して復旧する。
package store

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// readControlSnapshot は不完全・破損snapshotを修復しない。更新可能な復旧ではdeltaを開く前にSyncする。
func readControlSnapshot(dir string, m ControlManifest, validate ValueValidator, repair bool) (state ControlState, err error) {
	p := m.Snapshot
	if p == nil || p.Length > maxControlSnapshot {
		return state, ErrCorrupt
	}
	path := filepath.Join(dir, p.File)
	if err = privateRegular(path, false); err != nil {
		return state, err
	}
	mode := os.O_RDONLY
	if repair {
		mode = os.O_RDWR
	}
	f, err := os.OpenFile(path, mode, 0)
	if err != nil {
		return state, err
	}
	defer func() {
		err = errors.Join(err, f.Close())
		if err != nil {
			state = ControlState{}
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return state, err
	}
	if info.Size() != int64(p.Length) {
		return state, ErrCorrupt
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(p.Length)+1))
	if err != nil {
		return state, err
	}
	if len(raw) != int(p.Length) || sha256.Sum256(raw) != p.SHA {
		return state, ErrCorrupt
	}
	h := Header{Kind: m.Kind, Owner: m.Owner, Key: uint64(m.Subkey), BaseSeq: uint64(p.Seq), Generation: uint64(m.Generation)}
	state, err = DecodeControlSnapshot(raw, h, validate)
	if err != nil {
		return state, err
	}
	if repair {
		if err = f.Sync(); err != nil {
			return ControlState{}, err
		}
	}
	return state, nil
}
