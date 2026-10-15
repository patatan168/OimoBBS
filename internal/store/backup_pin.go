// 所有者の確定境界と読取りhandleを固定し、payloadコピーを所有処理列の外へ移す。
package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"oimobbs/internal/domain"
)

// ErrBackupPinBusy は同じ所有者に未解放のバックアップ固定があることを示す。
var ErrBackupPinBusy = errors.New("owner already has a pinned backup")

// ErrBackupPinBudget は捕捉時点の参照byte上限超過。
var ErrBackupPinBudget = errors.New("backup pin exceeds byte budget")

type pinnedBackupFile struct {
	file     *os.File
	name     string
	length   domain.U64
	expected *domain.Hash
}

// PinnedBackup は最大2つの読取りhandleと確定境界を保持する、一回だけ使えるコピー資源。
// Pinは所有者の処理列で行い、Copy/Closeは列の外で行える。必ずCopyまたはCloseで解放する。
// 開いた旧世代の物理容量はCloseまで解放されない。全体FD/容量/時間の予約は呼出元の責務。
type PinnedBackup struct {
	mu           sync.Mutex
	files        []pinnedBackupFile
	sourceDir    string
	cut          BackupCapture
	current      func(domain.Hash) ([]byte, error)
	lifetime     context.Context
	finish       func()
	stopLifetime func() bool
	release      func()
	closed       bool
}

// PinBackup は投稿logの確定末尾だけを所有処理列内で固定する。payloadの読取り/Syncは行わない。
// 同じlogへの未解放固定は一つまで。未知結果/停止中writerは拒否する。
func (t *ThreadLog) PinBackup(ctx context.Context) (*PinnedBackup, error) {
	return t.PinBackupLimited(ctx, 32<<30)
}

// PinBackupLimited は捕捉時のWAL/pack参照byte上限を開く前に検査する。
func (t *ThreadLog) PinBackupLimited(ctx context.Context, maxBytes uint64) (pin *PinnedBackup, err error) {
	total := uint64(t.end)
	if t.end < 64 || maxBytes == 0 || total > maxBytes {
		return nil, ErrBackupPinBudget
	}
	if t.manifest.Base != nil && uint64(t.manifest.Base.Length) > maxBytes-total {
		return nil, ErrBackupPinBudget
	}

	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if t.writer.stopped || t.end < 64 {
		return nil, ErrCorrupt
	}
	dir, e := filepath.Abs(t.dir)
	if e != nil {
		return nil, e
	}
	if !t.backupPinned.CompareAndSwap(false, true) {
		return nil, ErrBackupPinBusy
	}
	pin = &PinnedBackup{sourceDir: dir, release: func() { t.backupPinned.Store(false) }}
	defer func() {
		if err != nil {
			err = errors.Join(err, pin.Close())
			pin = nil
		}
	}()
	m := t.manifest
	if m.Base != nil {
		v := *m.Base
		m.Base = &v
	}
	delta, e := pinBackupFile(t.file.Name(), t.file, domain.U64(t.end), nil)
	if e != nil {
		return pin, e
	}
	pin.files = append(pin.files, delta)
	if m.Base != nil {
		base, e := pinBackupFile(filepath.Join(t.dir, m.Base.File), nil, m.Base.Length, &m.Base.SHA)
		if e != nil {
			return pin, e
		}
		pin.files = append(pin.files, base)
	}
	pin.cut = BackupCapture{CurrentName: "current.json", Sequence: t.state.Revision, RequiredEnd: domain.U64(t.end), Expires: t.state.Expires}
	m.Delta.RequiredSeq = pin.cut.Sequence
	m.Delta.RequiredEnd = pin.cut.RequiredEnd
	pin.current = func(hash domain.Hash) ([]byte, error) { m.Delta.RequiredSHA = hash; return EncodeCurrent(m) }
	return pin, nil
}

// PinBackup は復旧済み制御logの全確定末尾とsnapshot参照を、所有処理列内で固定する。
// currentの小さなmetadataだけを読み、WAL/snapshot payloadはCopyで処理する。
func (c *ControlLog) PinBackup(ctx context.Context) (*PinnedBackup, error) {
	return c.PinBackupLimited(ctx, 32<<30)
}

// PinBackupLimited は制御WAL/snapshotの合計参照量を読取りFDの取得前に制限する。
func (c *ControlLog) PinBackupLimited(ctx context.Context, maxBytes uint64) (pin *PinnedBackup, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if c.writer.stopped {
		return nil, ErrCorrupt
	}
	dir, e := filepath.Abs(filepath.Dir(c.file.Name()))
	if e != nil {
		return nil, e
	}
	if !c.backupPinned.CompareAndSwap(false, true) {
		return nil, ErrBackupPinBusy
	}
	pin = &PinnedBackup{sourceDir: dir, release: func() { c.backupPinned.Store(false) }}
	defer func() {
		if err != nil {
			err = errors.Join(err, pin.Close())
			pin = nil
		}
	}()
	m, e := InspectControlManifest(dir)
	if e != nil {
		return pin, e
	}
	if m.Kind != c.header.Kind || m.Owner != c.header.Owner || m.Subkey != domain.U64(c.header.Key) || m.Generation != domain.U64(c.header.Generation) || m.Delta.File != filepath.Base(c.file.Name()) || m.Delta.BaseSeq != domain.U64(c.header.BaseSeq) || (m.Snapshot == nil) != (c.snapshot == nil) {
		return pin, ErrCorrupt
	}
	info, e := c.file.Stat()
	if e != nil {
		return pin, e
	}
	if info.Size() < 64 || info.Size() > 16<<30 {
		return pin, ErrCorrupt
	}
	total := uint64(info.Size())
	if maxBytes == 0 || total > maxBytes || m.Snapshot != nil && uint64(m.Snapshot.Length) > maxBytes-total {
		return pin, ErrBackupPinBudget
	}
	delta, e := pinBackupFile(c.file.Name(), c.file, domain.U64(info.Size()), nil)
	if e != nil {
		return pin, e
	}
	pin.files = append(pin.files, delta)
	if m.Snapshot != nil {
		v := *m.Snapshot
		m.Snapshot = &v
		if c.snapshot == nil || *c.snapshot != v {
			return pin, ErrCorrupt
		}
		snap, e := pinBackupFile(filepath.Join(dir, v.File), nil, v.Length, &v.SHA)
		if e != nil {
			return pin, e
		}
		pin.files = append(pin.files, snap)
	}
	pin.cut = BackupCapture{CurrentName: "control.current", Sequence: c.state.Seq, RequiredEnd: domain.U64(info.Size())}
	m.Delta.RequiredSeq = pin.cut.Sequence
	m.Delta.RequiredEnd = pin.cut.RequiredEnd
	pin.current = func(hash domain.Hash) ([]byte, error) { m.Delta.RequiredSHA = hash; return encodeControlCurrent(m) }
	return pin, nil
}

// pinBackupFile はpathの新規読取りhandleを開き、現所有handleとのinode一致と長さを照合する。
func pinBackupFile(path string, owner *os.File, length domain.U64, expected *domain.Hash) (result pinnedBackupFile, err error) {
	if length < 64 || length > 16<<30 {
		return result, ErrCorrupt
	}
	if err = privateRegular(path, false); err != nil {
		return result, err
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return result, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, f.Close())
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return result, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != int64(length) {
		return result, ErrCorrupt
	}
	if owner != nil {
		actual, e := owner.Stat()
		if e != nil {
			return result, e
		}
		if !os.SameFile(info, actual) {
			return result, ErrCorrupt
		}
	}
	result = pinnedBackupFile{file: f, name: filepath.Base(path), length: length}
	if expected != nil {
		v := *expected
		result.expected = &v
	}
	return result, nil
}

// Copy は新規0700のtargetに固定prefixとコピー専用currentを保存し、成功時だけ境界を返す。
// ソースへ書き戻さず、失敗出力も削除しない。成功/失敗ともhandleを解放し、再利用を拒否する。
func (p *PinnedBackup) Copy(ctx context.Context, target string) (BackupCapture, error) {
	return p.copy(ctx, target, func(string) error { return nil })
}

// copy は列外の固定コピー。試験の境界で稼働側の追記/切替と並行させる。
func (p *PinnedBackup) copy(ctx context.Context, target string, checkpoint func(string) error) (cut BackupCapture, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.files) == 0 || p.release == nil {
		return cut, errors.New("backup pin already consumed or invalid")
	}

	if p.lifetime != nil {
		merged, cancel := context.WithCancel(ctx)
		stop := context.AfterFunc(p.lifetime, cancel)
		defer func() { stop(); cancel() }()
		if p.lifetime.Err() != nil {
			cancel()
		}
		ctx = managedBackupContext{Context: merged, lifetime: p.lifetime}
	}
	defer func() {
		err = errors.Join(err, p.closeLocked())
		if err != nil {
			cut = BackupCapture{}
		}
	}()
	if err = ctx.Err(); err != nil {
		return cut, err
	}
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || pathsOverlap(p.sourceDir, target) {
		return cut, errors.New("pinned copy requires separate clean absolute target")
	}
	if err = privatePinnedParent(filepath.Dir(target)); err != nil {
		return cut, err
	}
	if err = os.Mkdir(target, 0700); err != nil {
		return cut, err
	}
	if err = SyncDirectory(filepath.Dir(target)); err != nil {
		return cut, err
	}
	if err = checkpoint("backup:copy_start"); err != nil {
		return cut, err
	}
	cut = p.cut
	cut.Files = []BackupFile{}
	for i, file := range p.files {
		copied, e := copyPinnedBackupFile(ctx, file, filepath.Join(target, file.name))
		if e != nil {
			return cut, e
		}
		cut.Files = append(cut.Files, copied)
		if i == 0 {
			cut.Current, err = p.current(copied.SHA)
			if err != nil {
				return cut, err
			}
		}
	}
	if err = ctx.Err(); err != nil {
		return cut, err
	}
	if err = writePinnedCurrent(filepath.Join(target, cut.CurrentName), cut.Current); err != nil {
		return cut, err
	}
	if err = SyncDirectory(target); err != nil {
		return cut, err
	}
	if err = SyncDirectory(filepath.Dir(target)); err != nil {
		return cut, err
	}
	if err = ctx.Err(); err != nil {
		return cut, err
	}
	return cut, nil
}

// pathsOverlap は固定元とコピー先の重複/内包を拒否する。
func pathsOverlap(a, b string) bool {
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		rel, e := filepath.Rel(pair[0], pair[1])
		if e != nil || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// copyPinnedBackupFile はReadAtで固定長だけを読み、64KiBずつコピー・hash・取消確認する。
func copyPinnedBackupFile(ctx context.Context, pinned pinnedBackupFile, target string) (result BackupFile, err error) {
	f, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	hash := sha256.New()
	reader := io.NewSectionReader(pinned.file, 0, int64(pinned.length))
	buf := make([]byte, 64<<10)
	var count int64
	for count < int64(pinned.length) {
		if err = ctx.Err(); err != nil {
			return result, err
		}
		n, e := reader.Read(buf)
		if n > 0 {
			if err = writeFull(f, buf[:n]); err != nil {
				return result, err
			}
			_, _ = hash.Write(buf[:n])
			count += int64(n)
		}
		if e != nil && e != io.EOF {
			return result, e
		}
		if e == io.EOF {
			break
		}
	}
	if count != int64(pinned.length) {
		return result, io.ErrUnexpectedEOF
	}
	result = BackupFile{Name: pinned.name, Length: pinned.length}
	copy(result.SHA[:], hash.Sum(nil))
	if pinned.expected != nil && result.SHA != *pinned.expected {
		return result, ErrCorrupt
	}
	if err = f.Sync(); err != nil {
		return result, err
	}
	return result, nil
}

// writePinnedCurrent は全payload同期後のコピー専用currentを新規fileへ同期する。
func writePinnedCurrent(path string, raw []byte) (err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	if err = writeFull(f, raw); err != nil {
		return err
	}
	return f.Sync()
}

// Close はCopy完了まで待ち、未使用handleも解放する。繰り返し呼んでも安全。
func (p *PinnedBackup) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

// closeLocked はlease排他下で全読取りhandleと所有者の固定flagを解放する。
func (p *PinnedBackup) closeLocked() error {
	if p.closed {
		return nil
	}
	p.closed = true
	var err error
	for _, file := range p.files {
		err = errors.Join(err, file.file.Close())
	}
	p.files = nil
	p.current = nil
	if p.stopLifetime != nil {
		p.stopLifetime()
		p.stopLifetime = nil
	}
	if p.release != nil {
		p.release()
	}
	p.release = nil
	if p.finish != nil {
		p.finish()
	}
	p.finish = nil
	return err
}

// backupPinFlag は所有列外のCloseと所有列内のPinを原子的に接続する。
type backupPinFlag = atomic.Bool

// privatePinnedParent は専用親の権限と、祖先にsymlinkがないことを確認する。
func privatePinnedParent(path string) error {
	if e := privateRegular(path, true); e != nil {
		return e
	}
	for {
		info, e := os.Lstat(path)
		if e != nil {
			return e
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrCorrupt
		}
		parent := filepath.Dir(path)
		if parent == path {
			return nil
		}
		path = parent
	}
}

// Manage は未使用pinへ保持期限と予約解放を一度だけ接続する。
// 期限切れでは未使用pinを閉じ、Copy中は取消を伝える。finishはCloseを再入せず短く終了すること。
func (p *PinnedBackup) Manage(ctx context.Context, finish func()) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.lifetime != nil || finish == nil {
		return errors.New("backup pin cannot attach lifetime")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	p.lifetime = ctx
	p.finish = finish
	p.stopLifetime = context.AfterFunc(ctx, func() { _ = p.Close() })
	return nil
}

// managedBackupContext はAfterFuncの通知待ちでも保持期限の取消を同期的に検出する。
type managedBackupContext struct {
	context.Context
	lifetime context.Context
}

func (c managedBackupContext) Err() error {
	if e := c.lifetime.Err(); e != nil {
		return e
	}
	return c.Context.Err()
}

// ReferenceBytes は固定時の参照量を返す。使用済み資源では零を返す。
func (p *PinnedBackup) ReferenceBytes() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	var total uint64
	for _, f := range p.files {
		total += uint64(f.length)
	}
	return total
}

// Preview は固定予定のfile名/長さを返す。hashとcurrentはまだ生成していない。
// 回収予定集合の署名に使い、内容検証済みの成果とは扱わない。
func (p *PinnedBackup) Preview() (BackupCapture, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return BackupCapture{}, ErrCorrupt
	}
	c := p.cut
	c.Files = make([]BackupFile, 0, len(p.files))
	for _, f := range p.files {
		c.Files = append(c.Files, BackupFile{Name: f.name, Length: f.length})
	}
	raw, e := p.current(domain.Hash{})
	if e != nil {
		return BackupCapture{}, e
	}
	c.Current = raw
	return c, nil
}

// LimitExpiry は所有列で確認した元記録の期限を、コピー開始前の固定境界へ反映する。
// 後から期限を延長できず、解放済みhandleでは変更しない。
func (p *PinnedBackup) LimitExpiry(expires domain.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || expires < 0 {
		return ErrCorrupt
	}
	if expires != 0 && (p.cut.Expires == 0 || expires < p.cut.Expires) {
		p.cut.Expires = expires
	}
	return nil
}
