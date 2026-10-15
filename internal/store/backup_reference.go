// 閉じる制御logの検証済み参照を保持し、再生せずに固定読取りhandleを取得する。
package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"oimobbs/internal/domain"
)

// ControlBackupReference は確定済み第1世代制御logの値参照。所有列で作り、同じ列でPinする。
// 正本外からの変更を認めず、inode・長さ・currentの一致を再確認する。
type ControlBackupReference struct {
	dir      string
	info     os.FileInfo
	manifest ControlManifest
	cut      BackupCapture
}

// BackupReference はpayloadを読まず、監査/jobの確定位置を値として返す。
// snapshot世代は生きたControlLogのPinBackupLimitedを使う。
func (c *ControlLog) BackupReference(expires domain.Time) (ControlBackupReference, error) {
	if c.writer.stopped || c.header.Generation != 1 || c.snapshot != nil {
		return ControlBackupReference{}, ErrCorrupt
	}
	dir := filepath.Dir(c.file.Name())
	m, err := InspectControlManifest(dir)
	if err != nil {
		return ControlBackupReference{}, err
	}
	info, err := c.file.Stat()
	if err != nil {
		return ControlBackupReference{}, err
	}
	if m.Owner != c.header.Owner || m.Kind != c.header.Kind || m.Generation != 1 || m.Subkey != domain.U64(c.header.Key) || m.Snapshot != nil || m.Delta.File != filepath.Base(c.file.Name()) || info.Size() < 64 || info.Size() > 16<<30 {
		return ControlBackupReference{}, ErrCorrupt
	}
	return ControlBackupReference{dir, info, m, BackupCapture{CurrentName: "control.current", Sequence: c.state.Seq, RequiredEnd: domain.U64(info.Size()), Expires: expires}}, nil
}

// Pin は登録済み参照の同一inodeを固定する。payload hashとSyncはCopyへ委ねる。
func (r ControlBackupReference) Pin(ctx context.Context, maxBytes uint64) (p *PinnedBackup, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if r.info == nil {
		return nil, ErrCorrupt
	}
	if maxBytes == 0 || uint64(r.cut.RequiredEnd) > maxBytes {
		return nil, ErrBackupPinBudget
	}
	m, err := InspectControlManifest(r.dir)
	if err != nil {
		return nil, err
	}
	if m != r.manifest {
		return nil, ErrCorrupt
	}
	file, err := pinBackupFile(filepath.Join(r.dir, m.Delta.File), nil, r.cut.RequiredEnd, nil)
	if err != nil {
		return nil, err
	}
	p = &PinnedBackup{sourceDir: r.dir, files: []pinnedBackupFile{file}, cut: r.cut, release: func() {}}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
			p = nil
		}
	}()
	info, err := file.file.Stat()
	if err != nil {
		return p, err
	}
	if !os.SameFile(info, r.info) {
		return p, ErrCorrupt
	}
	m.Delta.RequiredSeq = r.cut.Sequence
	m.Delta.RequiredEnd = r.cut.RequiredEnd
	p.current = func(hash domain.Hash) ([]byte, error) { m.Delta.RequiredSHA = hash; return encodeControlCurrent(m) }
	return p, nil
}
