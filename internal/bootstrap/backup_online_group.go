// 板の制御・投稿・証拠を同じ所有処理列で固定し、有界な部品集合を列外でコピーする。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ErrOnlineBackupOwners は一括捕捉の所有者数上限超過。
var ErrOnlineBackupOwners = errors.New("online backup owner budget exceeded")

// OnlineBackupGroupOptions は板一括捕捉の合計参照量/工程時間/所有者数。零値は256MiB/30s/64件。
type OnlineBackupGroupOptions struct {
	MaxBytes  uint64
	Budget    time.Duration
	MaxOwners int
}

// OnlineBackupOwnerCapture は一つの部品の種類・配置と固定境界。公開HTTPへ出してはならない。
type OnlineBackupOwnerCapture struct {
	Kind       string
	Owner      domain.ID
	Subkey     string
	Capture    store.BackupCapture
	CapturedAt domain.Time
}

// OnlineBackupGroupCapture は部品コピーの結果。署名済み完成バックアップや公開復元の証明ではない。
type OnlineBackupGroupCapture struct {
	Captures       []OnlineBackupOwnerCapture
	ReferenceBytes domain.U64
}

type onlineBackupPart struct {
	kind       string
	owner      domain.ID
	subkey     string
	pin        *store.PinnedBackup
	capturedAt domain.Time
}

// OnlineBackupGroup は有限個の固定handleを一件の全体予約へ束縛する。Copy/Closeで早期解放する。
type OnlineBackupGroup struct {
	includeThreadAudit   bool
	optionalLogActive    bool
	requiredHoldBoards   []domain.ID
	optionalSiteSequence domain.U64
	metadataByteLimit    uint64

	mu            sync.Mutex
	sourceRoot    string
	parts         []onlineBackupPart
	bytes         uint64
	lifetime      context.Context
	cancel        context.CancelFunc
	release       func()
	stop          func() bool
	closed        bool
	maxOwners     int
	metadata      map[string][]byte
	metadataOwner domain.ID
	prefix        string
	beforeCopy    func() error
	clock         func() time.Time
	metadataAt    domain.Time
	install       func(func() error) error
}

// normalizeOnlineGroupOptions は台帳・FD・保持時間を受付前に有界化する。
func normalizeOnlineGroupOptions(o OnlineBackupGroupOptions) (OnlineBackupGroupOptions, error) {
	if o.MaxBytes == 0 {
		o.MaxBytes = onlineBackupDefaultBytes
	}
	if o.Budget == 0 {
		o.Budget = 30 * time.Second
	}
	if o.MaxOwners == 0 {
		o.MaxOwners = 64
	}
	if o.MaxBytes < 1<<20 || o.MaxBytes > 1<<30 || o.Budget < time.Second || o.Budget > 5*time.Minute || o.MaxOwners < 1 || o.MaxOwners > 256 {
		return o, errors.New("online group requires bytes 1MiB..1GiB, budget 1s..5m and owners 1..256")
	}
	return o, nil
}

// PinBoardBackup は板control・全thread・保存済みjournalを同じ空き所有列内でまとめて固定する。
// byte/件数超過は部分受付を返さず全解放する。監査/job/site/metadataの集約は含まない。
func (r *Repository) PinBoardBackup(ctx context.Context, owner domain.ID, options OnlineBackupGroupOptions) (*OnlineBackupGroup, error) {
	o, e := normalizeOnlineGroupOptions(options)
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	r.mu.Lock()
	e = r.available()
	b := r.posting[owner]
	r.mu.Unlock()
	if e != nil {
		return nil, e
	}
	if b == nil {
		return nil, ErrPostingUnavailable
	}
	life, cancel := context.WithTimeout(ctx, o.Budget)
	release, e := r.reserveOnlineBackup(o.MaxBytes)
	if e != nil {
		cancel()
		return nil, e
	}
	g := &OnlineBackupGroup{includeThreadAudit: true, sourceRoot: r.cfg.DataDir, lifetime: life, cancel: cancel, release: release}
	_, e = b.worker.SubmitIdle(life, func() (any, error) { return nil, b.pinBackupGroup(g, o) })
	if e != nil {
		return nil, errors.Join(e, g.Close())
	}
	g.attachLifetime()
	return g, nil
}

// pinBackupGroup は所有列内で並行投稿を止めたまま、小さな参照情報とFDだけを取得する。
func (b *postingBoard) pinBackupGroup(g *OnlineBackupGroup, o OnlineBackupGroupOptions) error {
	if b.stopped {
		return ErrPostingUnavailable
	}
	if len(b.journals) > o.MaxOwners {
		return ErrOnlineBackupOwners
	}
	keys := make([]uint64, 0, len(b.threads))
	for key := range b.threads {
		if b.threads[key].Reclaimed() {
			continue
		}
		keys = append(keys, key)
	}
	days := make([]uint64, 0, len(b.journals))
	for day, j := range b.journals {
		if j.HasPersistedLog() {
			days = append(days, day)
		}
	}
	auditOwners := 0
	if g.includeThreadAudit {
		auditOwners = len(b.auditRefs)
	}
	if 1+len(keys)+len(days)+len(b.deletions)+auditOwners > o.MaxOwners {
		return ErrOnlineBackupOwners
	}
	slices.Sort(keys)
	slices.Sort(days)
	if e := g.addPart("board", b.owner, "control", o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) { return b.control.PinBackupLimited(g.lifetime, limit) }); e != nil {
		return e
	}
	now := domain.Time(b.clock().UnixNano())
	for _, key := range keys {
		if e := g.addPart("thread", b.owner, fmt.Sprint(key), o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) {
			return b.threads[key].PinBackupLimited(g.lifetime, now, limit)
		}); e != nil {
			return e
		}
	}
	for _, day := range days {
		if e := g.addPart("evidence", b.owner, fmt.Sprint(day), o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) {
			return b.journals[day].PinBackupLimited(g.lifetime, limit)
		}); e != nil {
			return e
		}
	}
	deletedKeys := make([]uint64, 0, len(b.deletions))
	for key := range b.deletions {
		deletedKeys = append(deletedKeys, key)
	}
	slices.Sort(deletedKeys)
	for _, key := range deletedKeys {
		if e := g.addPart("deletion", b.owner, fmt.Sprint(key), o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) {
			return b.deletions[key].PinBackupLimited(g.lifetime, limit)
		}); e != nil {
			return e
		}
	}
	if g.includeThreadAudit {
		auditDays := make([]string, 0, len(b.auditRefs))
		for day := range b.auditRefs {
			auditDays = append(auditDays, day)
		}
		slices.Sort(auditDays)
		for _, day := range auditDays {
			ref := b.auditRefs[day]
			if e := g.addPart("audit", b.owner, day, o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) { return ref.Pin(g.lifetime, limit) }); e != nil {
				return e
			}
		}
	}
	return g.lifetime.Err()
}

// addPart は残りbyteだけを次の所有者へ渡し、固定資源を集合の解放対象へ加える。
func (g *OnlineBackupGroup) addPart(kind string, owner domain.ID, subkey string, limit uint64, pin func(uint64) (*store.PinnedBackup, error)) error {
	if e := g.lifetime.Err(); e != nil {
		return e
	}
	if g.maxOwners != 0 && len(g.parts) >= g.maxOwners {
		return ErrOnlineBackupOwners
	}
	if g.bytes >= limit {
		return store.ErrBackupPinBudget
	}
	p, e := pin(limit - g.bytes)
	if e != nil {
		return e
	}
	g.parts = append(g.parts, onlineBackupPart{kind, owner, subkey, p, g.captureTime()})
	g.bytes += p.ReferenceBytes()
	return nil
}

// attachLifetime は公開前に自動解放を接続する。取消が先行した場合もCloseする。
func (g *OnlineBackupGroup) attachLifetime() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.stop = context.AfterFunc(g.lifetime, func() { _ = g.Close() })
}

// Close はコピー終了を待ち、全handleを閉じてから一件分の予約を一度だけ解放する。
func (g *OnlineBackupGroup) Close() error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.closeLocked()
}

// closeLocked は集合排他の内側で全handleと予約を解放する。
func (g *OnlineBackupGroup) closeLocked() error {
	if g.closed {
		return nil
	}
	g.closed = true
	if g.stop != nil {
		g.stop()
		g.stop = nil
	}
	if g.cancel != nil {
		g.cancel()
	}
	var err error
	for _, part := range g.parts {
		err = errors.Join(err, part.pin.Close())
	}
	g.parts = nil
	if g.release != nil {
		g.release()
		g.release = nil
	}
	return err
}

// Copy は新規private rootへ部品集合をコピーし、成功/失敗とも全資源を解放する。
// コピー成功はサイト全体の整合性/署名/再生完了を意味しない。途中出力は削除しない。
func (g *OnlineBackupGroup) Copy(ctx context.Context, target string) (OnlineBackupGroupCapture, error) {
	return g.copy(ctx, target, func(int) error { return nil })
}

// copy は部品境界の試験注入と取消を含め、集合の単発コピーを直列化する。
func (g *OnlineBackupGroup) copy(ctx context.Context, target string, checkpoint func(int) error) (cut OnlineBackupGroupCapture, err error) {
	return g.copyFinalized(ctx, target, checkpoint, func(OnlineBackupGroupCapture) error { return nil })
}

// copyFinalized は照合/完成印の保存まで全体予約を維持する。
func (g *OnlineBackupGroup) copyFinalized(ctx context.Context, target string, checkpoint func(int) error, finalize func(OnlineBackupGroupCapture) error) (cut OnlineBackupGroupCapture, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || len(g.parts) == 0 {
		return cut, errors.New("online backup group already consumed")
	}
	defer func() {
		err = errors.Join(err, g.closeLocked())
		if err != nil {
			cut = OnlineBackupGroupCapture{}
		}
	}()
	merged, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.lifetime, cancel)
	defer func() { stop(); cancel() }()
	copyCtx := onlineGroupContext{merged, g.lifetime}
	if err = copyCtx.Err(); err != nil {
		return cut, err
	}
	if err = g.prepareTarget(target); err != nil {
		return cut, err
	}
	if g.beforeCopy != nil {
		if err = g.beforeCopy(); err != nil {
			return cut, err
		}
	}
	copyRoot := target
	if g.prefix != "" {
		copyRoot = filepath.Join(target, g.prefix)
		if err = makeBackupDirectories(target, copyRoot); err != nil {
			return cut, err
		}
	}
	cut.ReferenceBytes = domain.U64(g.bytes)
	for i, p := range g.parts {
		if err = checkpoint(i); err != nil {
			return cut, err
		}
		captured, e := copyOnlineBackupPart(copyCtx, copyRoot, p)
		if e != nil {
			return cut, e
		}
		cut.Captures = append(cut.Captures, OnlineBackupOwnerCapture{p.kind, p.owner, p.subkey, captured, p.capturedAt})
	}
	if len(g.metadata) > 0 {
		meta, e := copyOnlineMetadata(copyCtx, copyRoot, g.metadataOwner, g.metadata)
		if e != nil {
			return cut, e
		}
		meta.CapturedAt = g.metadataAt
		if meta.CapturedAt == 0 {
			meta.CapturedAt = g.captureTime()
		}
		cut.Captures = append(cut.Captures, meta)
	}
	if err = store.SyncDirectory(target); err != nil {
		return cut, err
	}
	if err = checkOnlineCaptureExpiry(cut.Captures); err != nil {
		return cut, err
	}
	if err = copyCtx.Err(); err != nil {
		return cut, err
	}
	if err = finalize(cut); err != nil {
		return cut, err
	}
	err = copyCtx.Err()
	return cut, err
}

// onlineGroupContext は取消通知goroutineの実行前でも保持期限を検出する。
type onlineGroupContext struct {
	context.Context
	lifetime context.Context
}

func (c onlineGroupContext) Err() error {
	if e := c.lifetime.Err(); e != nil {
		return e
	}
	return c.Context.Err()
}

// prepareTarget は正本外の新規private rootと容量を、payload書込み前に確認する。
func (g *OnlineBackupGroup) prepareTarget(target string) error {
	if !filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("online group target must be clean and absolute")
	}
	rel, e := filepath.Rel(g.sourceRoot, target)
	if e != nil || rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return errors.New("online group target overlaps source")
	}
	if err := backupCapacity(g.sourceRoot, filepath.Dir(target), g.bytes+onlineBackupOverhead); err != nil {
		return err
	}
	if err := privatePath(filepath.Dir(target), true); err != nil {
		return err
	}
	if err := os.Mkdir(target, 0700); err != nil {
		return err
	}
	if err := store.SyncDirectory(filepath.Dir(target)); err != nil {
		return err
	}
	return nil
}

// copyOnlineBackupPart は一所有者の配置・固定長コピー・元期限確認を行う。
func copyOnlineBackupPart(ctx context.Context, target string, p onlineBackupPart) (store.BackupCapture, error) {
	path := filepath.Join(target, p.kind, p.owner.String(), p.subkey)
	if e := makeBackupDirectories(target, filepath.Dir(path)); e != nil {
		return store.BackupCapture{}, e
	}
	captured, e := p.pin.Copy(ctx, path)
	if e != nil {
		return store.BackupCapture{}, e
	}
	if captured.Expires != 0 && time.Now().UnixNano() >= int64(captured.Expires) {
		return store.BackupCapture{}, errors.New("thread expired during group copy")
	}
	return captured, nil
}

// checkOnlineCaptureExpiry は最終化時に先にコピーしたスレッドの期限も再確認する。
func checkOnlineCaptureExpiry(captures []OnlineBackupOwnerCapture) error {
	now := time.Now().UnixNano()
	for _, c := range captures {
		if c.Capture.Expires != 0 && now >= int64(c.Capture.Expires) {
			return errors.New("thread expired before group completion")
		}
	}
	return nil
}

func (g *OnlineBackupGroup) captureTime() domain.Time {
	if g.clock != nil {
		return domain.Time(g.clock().UnixNano())
	}
	return domain.Time(time.Now().UnixNano())
}
