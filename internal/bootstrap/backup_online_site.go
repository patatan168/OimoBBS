// 全体予約を共有してサイト/板/監査/jobを捕捉し、列外コピー後に境界を照合する。
package bootstrap

import (
	"context"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ErrOnlineBackupChanged は捕捉中のサイト構造変更。部分集合を完成扱いせず新規出力で再試行する。
var ErrOnlineBackupChanged = errors.New("site changed during online backup")

// OnlineBackupSiteOptions は全サイト合計の参照量・時間・部品数・板数の上限。
// 零値は256MiB/30秒/256部品/64板。
type OnlineBackupSiteOptions struct {
	MaxBytes             uint64
	Budget               time.Duration
	MaxOwners, MaxBoards int
}

// OnlineBackupSiteCapture は照合済み部品集合。署名/鍵束完成や公開復元の許可ではない。
type OnlineBackupSiteCapture struct {
	OnlineBackupGroupCapture
	Site                        domain.ID
	MinimumReader               uint32
	Started, Completed, Expires domain.Time
	DeletionReportsOmitted      bool
	RestoreReady                bool
}

type onlineSiteBoundary struct {
	reportsOmitted bool
	state          siteState
	seq            domain.U64
	boards         []*postingBoard
	catalog        []onlineCatalogPart
	anchors        map[domain.ID]candidateOwner
	validation     map[domain.ID]*postingBoard
	epochs         map[domain.ID]uint64
}

func normalizeOnlineSiteOptions(o OnlineBackupSiteOptions) (OnlineBackupGroupOptions, int, error) {
	if o.MaxOwners == 0 {
		o.MaxOwners = 256
	}
	if o.MaxBoards == 0 {
		o.MaxBoards = 64
	}
	g, e := normalizeOnlineGroupOptions(OnlineBackupGroupOptions{o.MaxBytes, o.Budget, o.MaxOwners})
	if e == nil && (o.MaxBoards < 1 || o.MaxBoards > 64) {
		e = errors.New("online site requires boards 1..64")
	}
	return g, o.MaxBoards, e
}

// AssembleOnlineBackup は全所有者を新規private rootへ集約する。失敗時は空結果と資源解放を返す。
// 監査移管は事前に完了させる。manifestは生成せず、途中出力を推測削除しない。
func (r *Repository) AssembleOnlineBackup(ctx context.Context, target string, options OnlineBackupSiteOptions) (OnlineBackupSiteCapture, error) {
	return r.assembleOnlineBackup(ctx, target, options, time.Now, func(string) error { return nil }, nil)
}

func (r *Repository) assembleOnlineBackup(ctx context.Context, target string, options OnlineBackupSiteOptions, clock func() time.Time, checkpoint func(string) error, finish func(OnlineBackupSiteCapture) error) (result OnlineBackupSiteCapture, err error) {
	return r.assembleOnlineBackupWithSetup(ctx, target, options, clock, checkpoint, finish, nil)
}

func (r *Repository) assembleOnlineBackupWithSetup(ctx context.Context, target string, options OnlineBackupSiteOptions, clock func() time.Time, checkpoint func(string) error, finish func(OnlineBackupSiteCapture) error, setup func(*OnlineBackupGroup, time.Time) error) (result OnlineBackupSiteCapture, err error) {
	o, boards, e := normalizeOnlineSiteOptions(options)
	if e != nil {
		return result, e
	}
	if e = r.preflightOnlineTarget(target); e != nil {
		return result, e
	}
	if e = ctx.Err(); e != nil {
		return result, e
	}
	started := clock()
	life, cancel := context.WithTimeout(ctx, o.Budget)
	release, e := r.reserveOnlineBackup(o.MaxBytes)
	if e != nil {
		cancel()
		return result, e
	}
	g := &OnlineBackupGroup{sourceRoot: r.cfg.DataDir, lifetime: life, cancel: cancel, release: release, maxOwners: o.MaxOwners - 1, clock: clock, metadataAt: domain.Time(started.UnixNano())}
	defer func() {
		err = errors.Join(err, g.Close())
		if err != nil {
			result = OnlineBackupSiteCapture{}
		}
	}()
	boundary, e := r.pinOnlineSite(g, o, boards, started)
	if e != nil {
		return result, e
	}
	defer func() {
		for _, b := range boundary.validation {
			clear(b.key)
			clear(b.dedupKey[:])
		}
	}()
	if e = checkpoint("site_pinned"); e != nil {
		return result, e
	}
	for _, b := range boundary.boards {
		_, e = b.worker.SubmitIdle(life, func() (any, error) {
			boundary.epochs[b.owner] = b.deletionEpoch.Load()
			clone := &postingBoard{owner: b.owner, key: slices.Clone(b.key), dedupKey: b.dedupKey}
			baseValidator := b.validateBase
			clone.validate = func(raw []byte) error {
				if e := baseValidator(raw); e != nil {
					return e
				}
				return postcapture.ValidateKey(raw, clone.dedupKey)
			}
			boundary.validation[b.owner] = clone
			if e := b.pinBackupGroup(g, o); e != nil {
				return nil, e
			}
			return nil, pinOnlineCatalog(g, boundary.catalog, b.owner, o.MaxBytes, started)
		})
		if e != nil {
			return result, e
		}
		if e = checkpoint("board_pinned"); e != nil {
			return result, e
		}
	}
	g.install = func(run func() error) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		if e := r.checkOnlineSiteBoundaryLocked(boundary); e != nil {
			return e
		}
		return run()
	}
	if setup != nil {
		if e = setup(g, started); e != nil {
			return result, e
		}
	}
	_, err = g.copyFinalized(ctx, target, func(int) error { return checkpoint("copy_part") }, func(cut OnlineBackupGroupCapture) error {
		if e := r.validateOnlineSiteCopy(life, filepath.Join(target, g.prefix), boundary, cut); e != nil {
			return e
		}
		if e := checkpoint("validated"); e != nil {
			return e
		}
		if e := r.checkOnlineSiteBoundary(boundary); e != nil {
			return e
		}
		now := clock()
		expires := domain.Time(started.Add(backupRetention).UnixNano())
		for _, c := range cut.Captures {
			if c.Capture.Expires != 0 {
				expires = min(expires, c.Capture.Expires)
			}
		}
		if now.Before(started) || now.UnixNano() >= int64(expires) {
			return errors.New("online site clock regression or expiry")
		}
		result = OnlineBackupSiteCapture{DeletionReportsOmitted: boundary.reportsOmitted, OnlineBackupGroupCapture: cut, Site: boundary.state.ID, MinimumReader: boundary.state.MinimumReader, Started: domain.Time(started.UnixNano()), Completed: domain.Time(now.UnixNano()), Expires: expires}
		if finish != nil {
			return finish(result)
		}
		return nil
	})
	return result, err
}

// pinOnlineSite は管理mutex内でサイト境界と検証済み参照を固定する。板ワーカーは待たない。
func (r *Repository) pinOnlineSite(g *OnlineBackupGroup, o OnlineBackupGroupOptions, maxBoards int, now time.Time) (v onlineSiteBoundary, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err = r.available(); err != nil {
		return v, err
	}
	if r.onlineCatalog == nil {
		return v, ErrPostingUnavailable
	}
	if len(r.boards) > maxBoards || len(r.posting) != len(r.boards) || len(r.onlineCatalog.parts) > o.MaxOwners {
		return v, ErrOnlineBackupOwners
	}
	if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &v.state); err != nil {
		return v, err
	}
	dirs, e := siteDirectories(r.site.State())
	if e != nil {
		return v, e
	}
	if len(dirs) != len(r.boards) {
		return v, store.ErrIncomplete
	}
	for id, dir := range dirs {
		b := r.posting[id]
		if dir.Status != "active" || b == nil || b.control != r.boards[id] {
			return v, ErrPostingUnavailable
		}
		v.boards = append(v.boards, b)
	}
	slices.SortFunc(v.boards, func(a, b *postingBoard) int { return strings.Compare(a.owner.String(), b.owner.String()) })
	v.validation = map[domain.ID]*postingBoard{}
	v.epochs = map[domain.ID]uint64{}
	_, v.reportsOmitted = r.site.State().Rows["report_store:active"]
	v.seq = r.site.State().Seq
	v.anchors = make(map[domain.ID]candidateOwner, len(r.anchors))
	for id, a := range r.anchors {
		v.anchors[id] = a
	}
	for _, p := range r.onlineCatalog.parts {
		v.catalog = append(v.catalog, p)
	}
	slices.SortFunc(v.catalog, func(a, b onlineCatalogPart) int {
		return strings.Compare(a.kind+"/"+a.owner.String()+"/"+a.subkey, b.kind+"/"+b.owner.String()+"/"+b.subkey)
	})
	n, e := catalogMetadataBytes(r.onlineCatalog.metadata)
	if e != nil {
		return v, e
	}
	if n >= o.MaxBytes {
		return v, store.ErrBackupPinBudget
	}
	g.optionalLogActive, e = backupOptionalEnabled(r.site.State(), v.state.ID)
	if e != nil {
		return v, e
	}
	g.requiredHoldBoards, e = backupRequiredBoards(r.site.State(), v.state.ID)
	if e != nil {
		return v, e
	}
	g.optionalSiteSequence = v.seq
	g.metadataByteLimit = o.MaxBytes
	g.bytes = n
	g.metadataOwner = v.state.ID
	g.metadata = make(map[string][]byte, len(r.onlineCatalog.metadata))
	for name, raw := range r.onlineCatalog.metadata {
		g.metadata[name] = slices.Clone(raw)
	}
	if err = g.addPart("site", v.state.ID, "control", o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) { return r.site.PinBackupLimited(g.lifetime, limit) }); err != nil {
		return v, err
	}
	if err = pinOnlineCatalog(g, v.catalog, v.state.ID, o.MaxBytes, now); err != nil {
		return v, err
	}
	for _, p := range v.catalog {
		if p.kind != "job" {
			continue
		}
		if p.expires == 0 {
			return v, store.ErrIncomplete
		}
		if p.expires <= domain.Time(now.UnixNano()) {
			continue
		}
		if err = g.addPart(p.kind, p.owner, p.subkey, o.MaxBytes, func(limit uint64) (*store.PinnedBackup, error) { return p.reference.Pin(g.lifetime, limit) }); err != nil {
			return v, err
		}
	}
	return v, g.lifetime.Err()
}

func pinOnlineCatalog(g *OnlineBackupGroup, catalog []onlineCatalogPart, owner domain.ID, maxBytes uint64, now time.Time) error {
	for _, p := range catalog {
		if p.kind != "audit" || p.owner != owner {
			continue
		}
		if p.expires != 0 && p.expires <= domain.Time(now.UnixNano()) {
			return errors.New("expired audit requires maintenance before online backup")
		}
		if e := g.addPart(p.kind, p.owner, p.subkey, maxBytes, func(limit uint64) (*store.PinnedBackup, error) { return p.reference.Pin(g.lifetime, limit) }); e != nil {
			return e
		}
	}
	return nil
}

func (r *Repository) checkOnlineSiteBoundary(v onlineSiteBoundary) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.checkOnlineSiteBoundaryLocked(v)
}

func (r *Repository) checkOnlineSiteBoundaryLocked(v onlineSiteBoundary) error {
	if e := r.available(); e != nil {
		return e
	}
	if r.site.State().Seq != v.seq || len(r.posting) != len(v.boards) {
		return ErrOnlineBackupChanged
	}
	for _, b := range v.boards {
		if r.posting[b.owner] != b || b.deletionEpoch.Load() != v.epochs[b.owner] {
			return ErrOnlineBackupChanged
		}
	}
	return nil
}

// copyOnlineMetadata は起動時認証済みbyteを値コピーし、元pathを読み直さない。
func copyOnlineMetadata(ctx context.Context, target string, owner domain.ID, values map[string][]byte) (OnlineBackupOwnerCapture, error) {
	capture := OnlineBackupOwnerCapture{Kind: "metadata", Owner: owner, Subkey: "bootstrap", CapturedAt: domain.Time(time.Now().UnixNano())}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if e := ctx.Err(); e != nil {
			return capture, e
		}
		path := filepath.Join(target, "metadata", owner.String(), "bootstrap", filepath.FromSlash(name))
		if e := makeBackupDirectories(target, filepath.Dir(path)); e != nil {
			return capture, e
		}
		if e := writeNew(path, values[name]); e != nil {
			return capture, e
		}
		capture.Capture.Files = append(capture.Capture.Files, store.BackupFile{Name: name, Length: domain.U64(len(values[name])), SHA: sha256.Sum256(values[name])})
	}
	return capture, nil
}
