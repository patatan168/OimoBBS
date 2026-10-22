// 所有者を停止した状態で、バックアップ用currentを全確定prefixへ固定する。
package store

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"

	"oimobbs/internal/domain"
)

// BackupFile は保持対象ファイルの確定末尾と照合値。Nameは保存先内の単独名。
type BackupFile struct {
	Name   string
	Length domain.U64
	SHA    domain.Hash
}

// BackupCapture は鍵を含まない捕捉境界。Currentはコピー先専用で正本へ書き戻さない。
type BackupCapture struct {
	CurrentName string
	Current     []byte
	Sequence    domain.U64
	RequiredEnd domain.U64
	Expires     domain.Time
	Files       []BackupFile
}

// HashBackupFile は通常ファイルを64KiBのbufferで照合し、途中の取消を確認する。
func HashBackupFile(ctx context.Context, path string) (result BackupFile, err error) {
	if err = ctx.Err(); err != nil {
		return result, err
	}
	if err = privateRegular(path, false); err != nil {
		return result, err
	}
	f, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer func() {
		if e := f.Close(); err == nil {
			err = e
		}
	}()
	info, err := f.Stat()
	if err != nil || info.Size() < 0 || uint64(info.Size()) > 16<<30 {
		return result, ErrCorrupt
	}
	hash := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, e := f.Read(buf)
		if n > 0 {
			total += int64(n)
			_, _ = hash.Write(buf[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return result, e
		}
	}
	if total != info.Size() {
		return result, ErrCorrupt
	}
	result = BackupFile{Name: filepath.Base(path), Length: domain.U64(total)}
	copy(result.SHA[:], hash.Sum(nil))
	return result, nil
}

// BackupCapture は復旧済みcontrolの現在seqと実WAL末尾をcurrentへ固定する。
// 呼出元が所有者の変更を止め、確定済み末尾を持つhandleからだけ呼ぶ。
func (c *ControlLog) BackupCapture(ctx context.Context) (BackupCapture, error) {
	if c.writer.stopped {
		return BackupCapture{}, ErrCorrupt
	}
	dir := filepath.Dir(c.file.Name())
	m, e := InspectControlManifest(dir)
	if e != nil {
		return BackupCapture{}, e
	}
	file, e := HashBackupFile(ctx, c.file.Name())
	if e != nil {
		return BackupCapture{}, e
	}
	m.Delta.RequiredSeq = c.state.Seq
	m.Delta.RequiredEnd = file.Length
	m.Delta.RequiredSHA = file.SHA
	current, e := encodeControlCurrent(m)
	if e != nil {
		return BackupCapture{}, e
	}
	cut := BackupCapture{CurrentName: "control.current", Current: current, Sequence: c.state.Seq, RequiredEnd: file.Length, Files: []BackupFile{file}}
	if m.Snapshot != nil {
		snap, e := HashBackupFile(ctx, filepath.Join(dir, m.Snapshot.File))
		if e != nil || snap.Length != m.Snapshot.Length || snap.SHA != m.Snapshot.SHA {
			return BackupCapture{}, ErrCorrupt
		}
		cut.Files = append(cut.Files, snap)
	}
	return cut, nil
}

// BackupCapture は復旧済みthreadの現行packと全確定deltaだけを捕捉する。
func (t *ThreadLog) BackupCapture(ctx context.Context) (BackupCapture, error) {
	if t.writer.stopped {
		return BackupCapture{}, ErrCorrupt
	}
	file, e := HashBackupFile(ctx, t.file.Name())
	if e != nil {
		return BackupCapture{}, e
	}
	if uint64(file.Length) != uint64(t.end) {
		return BackupCapture{}, ErrCorrupt
	}
	m := t.manifest
	m.Delta.RequiredSeq = t.state.Revision
	m.Delta.RequiredEnd = file.Length
	m.Delta.RequiredSHA = file.SHA
	current, e := EncodeCurrent(m)
	if e != nil {
		return BackupCapture{}, e
	}
	cut := BackupCapture{CurrentName: "current.json", Current: current, Sequence: t.state.Revision, RequiredEnd: file.Length, Expires: t.state.Expires, Files: []BackupFile{file}}
	if m.Base != nil {
		pack, e := HashBackupFile(ctx, filepath.Join(t.dir, m.Base.File))
		if e != nil || pack.Length != m.Base.Length || pack.SHA != m.Base.SHA {
			return BackupCapture{}, ErrCorrupt
		}
		cut.Files = append(cut.Files, pack)
	}
	return cut, nil
}
