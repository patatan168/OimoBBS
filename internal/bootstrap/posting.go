// サイト排他の下で、板ワーカー・予約高水位・日別記録・投稿正本を接続する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var ErrPostingUnavailable = errors.New("posting writer unavailable")

// RepositoryPostingResult は板内のスレ立て再送にも元のキーを返す。
type RepositoryPostingResult struct {
	app.PostingResult
	ThreadKey uint64
}

type postingBoard struct {
	liveMetadata              atomic.Pointer[boardMetadata]
	collection                postingCollection
	formSettings              *postingFormSettings
	reservePreparationMemory  func(uint64) (func(), bool)
	parallelCaptureValidation bool
	captureMetadataMu         sync.Mutex
	guard                     *abuseGuard
	receipt                   atomic.Pointer[app.PostingSnapshot]
	listingStopped            atomic.Bool
	liveNetworks              *atomic.Pointer[identity.NetworkClassifier]
	readingNetworks           atomic.Pointer[[]identity.NetworkClass]
	checkPostingReading       func([]byte) error
	networkHosts              *identity.HostCache
	rememberAudit             func(string, *store.ControlLog) error
	auditRefs                 map[string]store.ControlBackupReference

	controlExpiryFloor                                              *atomic.Int64
	liveCaps                                                        *atomic.Pointer[capRegistry]
	capKey                                                          domain.Hash
	capCommitted                                                    map[domain.ID]domain.Time
	reserveDeletionPack                                             func() (func(), error)
	expiryHeap                                                      expiryHeap
	expirySiteVersion                                               domain.U64
	currentSiteRevision                                             func() domain.U64
	retentionEnabled                                                bool
	carryEnabled                                                    bool
	bodyReclaimEnabled                                              bool
	redactionCleanupAfter                                           string
	expiryWake                                                      chan struct{}
	expiryCancel                                                    context.CancelFunc
	expiryDone                                                      chan struct{}
	reserveCapacity                                                 func(...uint64) (func(), error)
	denials                                                         map[domain.ID]compiledDenial
	admission                                                       *admission
	postingPolicy                                                   boardPostingPolicy
	dedupKey, publicKey, slipNetKey, slipUAKey, confirmKey, csrfKey domain.Hash
	slug                                                            string
	createRequests                                                  map[createRequestKey]uint64
	publicName                                                      string
	autoReports                                                     atomic.Pointer[boardAutoReportSettings]
	hidden                                                          atomic.Bool
	noReprint                                                       atomic.Bool
	owner                                                           domain.ID
	root, threadsDir, evidenceDir                                   string
	control                                                         *store.ControlLog
	worker                                                          *board.Worker
	postBatch                                                       *board.Batch
	group                                                           *postingGroup
	sharedThreadWAL                                                 *store.ThreadCommitGroup
	threads                                                         map[uint64]*app.PostingLog
	publicReaders                                                   sync.Map // uint64 -> *app.PublicReader。DAT配列は複製しない。
	journals                                                        map[uint64]*evidence.Journal
	requiredRetirementEnabled                                       bool
	requiredRejectedEnabled                                         bool
	requiredHolds                                                   *app.RequiredOriginalHolds
	key                                                             ed25519.PrivateKey
	validate                                                        func([]byte) error
	validateBase                                                    func([]byte) error
	checkpoint                                                      func(string)
	clock                                                           func() time.Time
	stopped                                                         bool
	packsEnabled                                                    bool
	operations                                                      map[domain.ID]uint64
	deletions                                                       map[uint64]*store.ControlLog
	threadActionRecords                                             map[domain.ID]ThreadActionRecord
	deletionCheckpoint                                              func(string) error
	deletionEpoch                                                   atomic.Uint64
}

// PostingOptions は読み取り専用capture検証器の並行呼出し可否を指定する。
// 有効時の検証器は入力を変更せず、並行呼出しで共有状態を変更してはならない。
type PostingOptions struct{ ParallelCaptureValidation bool }

// OpenPostingRepository は完全なcapture検証器を必須とする内部の投稿対応起動。
// HTTP入力の認可・正規化・板設定適用・HMAC生成は上位層で行う。
// options省略時は外部検証器の呼出しを直列に保つ。CLI checkは投稿用検証器を持たない。
func OpenPostingRepository(cfg Config, validateCapture func([]byte) error, options ...PostingOptions) (*Repository, error) {
	if validateCapture == nil {
		return nil, errors.New("posting capture validator required")
	}
	return openPostingRepository(cfg, func(string) {}, validateCapture, options...)
}

// Post は板の有界列へ投入する。key=0はキー予約前に板内のcreate再送を照合する。
// 投稿処理開始後はcontext取消にかかわらず保存結果を確定する。
func (r *Repository) Post(ctx context.Context, owner domain.ID, key uint64, prepared, capture []byte) RepositoryPostingResult {
	started := time.Now()
	fail := func(e error) RepositoryPostingResult {
		return RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}}
	}
	if len(prepared) > store.MaxFrameBody+128 || len(capture) > 512<<10 {
		return fail(errors.New("posting input exceeds limit"))
	}
	b, e := r.postingOwner(owner)
	if e != nil {
		return fail(e)
	}
	prepared = bytes.Clone(prepared)
	capture = bytes.Clone(capture)
	value, e := r.submitPostingBatch(ctx, b, key, func() (any, error) {
		return b.post(key, prepared, capture), nil
	})
	if e != nil {
		return fail(e)
	}
	result := value.(RepositoryPostingResult)
	r.recordPostingLatency(started, result)
	return result
}

// Thread は板ワーカー上で確定済み公開snapshotを取得する。存在しない/期限切れならnil。
func (r *Repository) Thread(ctx context.Context, owner domain.ID, key uint64) (*app.PostingSnapshot, error) {
	b, e := r.postingOwner(owner)
	if e != nil {
		return nil, e
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		var snapshot *app.PostingSnapshot
		if p := b.threads[key]; p != nil {
			snapshot = p.Snapshot(domain.Time(b.clock().UnixNano()))
		}
		return snapshot, nil
	})
	if e != nil {
		return nil, e
	}
	return value.(*app.PostingSnapshot), nil
}
func (r *Repository) postingOwner(owner domain.ID) (*postingBoard, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e := r.available(); e != nil {
		return nil, e
	}
	b := r.posting[owner]
	if b == nil {
		return nil, errors.New("board not active for posting")
	}
	return b, nil
}

func (b *postingBoard) post(key uint64, prepared, capture []byte) RepositoryPostingResult {
	frame, _, err := store.ReadFrame(bytes.NewReader(prepared))
	if err == nil && len(frame.Records) == 1 {
		if op, e := domain.ParseOperation(frame.Records[0].JSON); e == nil && op.Actor.Kind == "cap" {
			return formFailure(ErrCap)
		}
	}
	proof, _, _, e := postcapture.CapMetadata(capture)
	if e != nil || proof != nil {
		return formFailure(ErrCap)
	}
	if b.admission != nil {
		return formFailure(ErrPostingUnavailable)
	}
	return b.postAdmitted(key, prepared, capture)
}
func (b *postingBoard) postAdmitted(key uint64, prepared, capture []byte) RepositoryPostingResult {
	return b.postAdmittedMetadata(key, prepared, capture, nil)
}

// postAdmittedMetadata は構築時の完全検証済みmetadataを同じ呼出し内で再利用する。
// 独立した元byte照合はbatch保存前に並行実行し、認可と候補適用は所有列に残す。
func (b *postingBoard) postAdmittedMetadata(key uint64, prepared, capture []byte, metadata *postcapture.Capture) RepositoryPostingResult {
	return b.postAdmittedPrepared(key, prepared, capture, metadata, nil)
}

// postAdmittedPrepared は構築済み候補があれば元byteを照合して復号結果を借用する。
func (b *postingBoard) postAdmittedPrepared(key uint64, prepared, capture []byte, metadata *postcapture.Capture, built *app.PreparedPosting) RepositoryPostingResult {
	return b.postAdmittedCandidate(key, prepared, capture, metadata, built, nil)
}

// postAdmittedCandidate は元frameから計算した比較材料も同じ構築呼出し内で借用する。
// 認可・受理枠・検出履歴の更新は所有列上で従来通り実行する。
func (b *postingBoard) postAdmittedCandidate(key uint64, prepared, capture []byte, metadata *postcapture.Capture, built *app.PreparedPosting, guard *guardEntry) RepositoryPostingResult {
	if b.group != nil {
		b.group.finishPreparations()
	}
	fail := func(e error) RepositoryPostingResult {
		return RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}, ThreadKey: key}
	}
	if b.stopped {
		return fail(errors.New("board writer stopped; reopen for recovery"))
	}
	if b.controlExpiryFloor != nil && b.clock().UnixNano() < b.controlExpiryFloor.Load() {
		return fail(ErrControlExpiryClock)
	}
	var frame store.Frame
	var op domain.Operation
	var rate app.RateRecord
	var e error
	if built != nil {
		if !built.Matches(prepared) {
			return fail(store.ErrCorrupt)
		}
		frame, op, rate = built.Metadata()
	} else {
		var n int64
		frame, n, e = store.ReadFrame(bytes.NewReader(prepared))
		if e != nil || n != int64(len(prepared)) || len(frame.Records) != 1 {
			return fail(store.ErrCorrupt)
		}
		op, e = domain.ParseOperation(frame.Records[0].JSON)
		if e != nil {
			return fail(e)
		}
	}
	if key == 0 && op.Type != "create" || key != 0 && op.Type != "append" || op.Dedup == nil {
		return fail(errors.New("posting route and operation differ"))
	}
	deferred := metadata != nil && b.group != nil && key != 0
	if deferred {
		day, _ := strconv.ParseUint(time.Unix(0, int64(metadata.Observation.Received)).UTC().Format("20060102"), 10, 64)
		journal := b.journals[day]
		deferred = journal != nil && journal.BatchReady()
	}
	if deferred {
		if !b.parallelCaptureValidation {
			if e = b.validateBase(capture); e != nil {
				return fail(e)
			}
		}
		if e = b.validateCaptureMetadata(metadata); e != nil {
			return fail(e)
		}
	} else {
		if e = b.validate(capture); e != nil {
			return fail(e)
		}
		metadata, e = postcapture.ValidateFrameAndMetadata(capture, prepared, key)
		if e != nil {
			return fail(e)
		}
	}
	if op.Actor.Kind == "cap" && (metadata == nil || metadata.Cap == nil) {
		return fail(ErrCap)
	}
	if b.checkPostingReading != nil {
		if err := b.checkPostingReading(capture); err != nil {
			return fail(err)
		}
	}
	if built == nil {
		rate, e = app.FrameRateRecord(prepared)
		if e != nil {
			return fail(e)
		}
	}
	if b.admission == nil && len(rate.Keys) != 0 {
		var marker struct {
			Schema string `json:"schema"`
		}
		err := json.Unmarshal(capture, &marker)
		if err != nil || (marker.Schema == postcapture.Schema) {
			return fail(ErrPostingUnavailable)
		}
	}
	if metadata != nil {
		rate.Schema, rate.TokenStatus, rate.Token = metadata.Schema, metadata.TokenValidation, metadata.Token
		rate.Overrides = metadata.Overrides
	} else {
		rate.Schema, rate.TokenStatus, rate.Token, e = postcapture.TokenMetadata(capture)
		if e == nil {
			_, _, rate.Overrides, e = postcapture.OverrideMetadata(capture)
		}
	}
	if e != nil {
		return fail(e)
	}
	if b.admission != nil {
		if rate.At < b.admission.policy.Enabled {
			return fail(ErrPostingUnavailable)
		}
		if e = b.admission.validate(b.owner, rate); e != nil {
			return fail(e)
		}
	}
	now := b.clock()
	at := domain.Time(now.UnixNano())
	var observation *evidence.HTTPObservation
	if metadata != nil {
		observation = &metadata.Observation
	} else {
		observation, e = evidence.PostingHTTPObservation(capture)
	}
	if e != nil {
		return fail(e)
	} else if observation != nil && !deferred {
		day, _ := strconv.ParseUint(time.Unix(0, int64(observation.Received)).UTC().Format("20060102"), 10, 64)
		if e = observation.ValidatePosting(b.owner, day, op); e != nil {
			return fail(e)
		}
	}
	validateCandidate := func() error {
		if b.parallelCaptureValidation {
			if err := b.validateBase(capture); err != nil {
				return err
			}
		}
		if _, err := postcapture.ValidateKeyAndFrameMetadata(capture, prepared, key, b.dedupKey); err != nil {
			return err
		}
		if observation != nil {
			day, _ := strconv.ParseUint(time.Unix(0, int64(observation.Received)).UTC().Format("20060102"), 10, 64)
			return observation.ValidatePosting(b.owner, day, op)
		}
		return nil
	}

	if op.Dedup.Mode == "explicit" {
		if result, ok := b.explicitRetry(op.Dedup, at); ok {
			if deferred {
				if err := validateCandidate(); err != nil {
					return fail(err)
				}
			}
			return result
		}
	}
	// 確定済み再送は容量不足でも元結果を返し、新たな保存を行わない。
	if key == 0 {
		if oldKey, exists := b.createRequests[createRequest(op.Dedup)]; exists {
			if result, ok := b.threads[oldKey].CreateRetry(op.Dedup, at); ok {
				if deferred {
					if err := validateCandidate(); err != nil {
						return fail(err)
					}
				}
				return RepositoryPostingResult{result, oldKey}
			}
		}
	} else if p := b.threads[key]; p != nil {
		if result, ok := p.Retry(op.Dedup, at); ok {
			if deferred {
				if err := validateCandidate(); err != nil {
					return fail(err)
				}
			}
			return RepositoryPostingResult{result, key}
		}
	}
	var candidate guardEntry
	var err error
	if guard != nil && built != nil {
		candidate = *guard
	} else {
		candidate, err = b.guardCandidate(op, frame.Records[0].ID, key, rate)
		if err != nil {
			return fail(err)
		}
	}
	if err = b.reserveGuard(candidate); err != nil {
		return fail(err)
	}
	guardRetained := false
	defer func() {
		if !guardRetained {
			b.settleGuard(candidate.id, false)
		}
	}()
	if b.reserveCapacity != nil {
		// 固定一件枠ではなく、保持するframe/captureと符号化時の複製分から作業量を見積もる。
		release, err := b.reserveCapacity((4 << 20) + uint64(len(prepared)+len(capture))*16)
		if err != nil {
			if errors.Is(err, errPostingMemory) && b.group != nil && b.group.hasPrepared() {
				// 準備済み分を確定して予約を解放し、現在の操作を同じ所有列で再試行する。
				b.group.full = true
				return fail(errPostingRebuild)
			}
			return fail(err)
		}
		defer func() {
			if b.group != nil && b.group.hasPrepared() {
				b.group.releases = append(b.group.releases, release)
			} else {
				release()
			}
		}()
	}
	if key == 0 {
		request := createRequest(op.Dedup)
		if oldKey, exists := b.createRequests[request]; exists {
			if result, ok := b.threads[oldKey].CreateRetry(op.Dedup, at); ok {
				return RepositoryPostingResult{result, oldKey}
			}
			delete(b.createRequests, request)
		}
		if _, used := b.operations[frame.Records[0].ID]; used {
			return fail(errors.New("operation ID already used"))
		}
		// 無効な候補で予約高水位を消費しない。
		if _, e = store.ValidateThreadFrame(nil, prepared); e != nil {
			return fail(e)
		}
		key, e = b.reserve(now)
		if e != nil {
			return fail(e)
		}
	} else if b.threads[key] == nil {
		return fail(errors.New("thread does not exist"))
	}
	if oldKey, used := b.operations[frame.Records[0].ID]; used && oldKey != key {
		return fail(errors.New("operation ID belongs to another thread"))
	}
	journalTime := now
	if observation != nil {
		journalTime = time.Unix(0, int64(observation.Received))
	}
	active, e := b.journal(journalTime)
	if e != nil {
		b.stopped = true
		return RepositoryPostingResult{PostingResult: app.PostingResult{CommitResult: store.CommitResult{Status: store.Unknown, Err: e}}, ThreadKey: key}
	}
	p := b.threads[key]
	if p == nil {
		p, e = app.OpenPosting(b.threadsDir, b.owner, key, []*evidence.Journal{active}, active, at)
		if e != nil {
			b.stopped = true
			return fail(e)
		}
		b.threads[key] = p
		b.publicReaders.Store(key, p.PublicReader())
	} else if b.group != nil && b.group.hasPrepared() && !b.group.batch.Fits(p, prepared, capture) {
		b.group.flush()
		if b.group.rebuild {
			return fail(errPostingRebuild)
		}
		if b.stopped {
			return fail(ErrPostingUnavailable)
		}
	}
	if e = p.UseJournal(active); e != nil {
		b.stopped = true
		return fail(e)
	}
	var result app.PostingResult
	if b.group != nil && key != 0 && b.group.batch.Fits(p, prepared, capture) {
		if built != nil {
			result = b.group.batch.StagePrepared(b.group.ctx, p, prepared, capture, at, built)
		} else {
			result = b.group.batch.Stage(b.group.ctx, p, prepared, capture, at)
		}
	} else {
		if b.group != nil {
			b.group.flush()
			if b.group.rebuild {
				return fail(errPostingRebuild)
			}
			if b.stopped {
				return fail(ErrPostingUnavailable)
			}
		}
		if deferred {
			if err := validateCandidate(); err != nil {
				return fail(err)
			}
		}
		result = p.Post(context.Background(), prepared, capture, at)
	}
	if deferred && errors.Is(result.Err, app.ErrPostingPrepared) && !result.Duplicate {
		b.group.validations = append(b.group.validations, postingValidation{index: b.group.current, check: validateCandidate, capture: capture})
	}

	if !result.Duplicate && (result.Status == store.Durable || errors.Is(result.Err, app.ErrPostingPrepared)) {
		b.updateGuardCandidate(candidate.id, key, result.PostNumber)
		guardRetained = true
		if errors.Is(result.Err, app.ErrPostingPrepared) {
			b.group.settlers = append(b.group.settlers, func(saved store.CommitResult) error {
				b.settleGuard(candidate.id, saved.Status == store.Durable)
				return nil
			})
		} else {
			b.settleGuard(candidate.id, true)
		}
	}
	if result.Status == store.Durable && op.Type == "create" {
		b.createRequests[createRequest(op.Dedup)] = key
		if b.expiryCancel != nil {
			b.bindExpiry(key, p)
		}
	}
	if result.Status == store.Durable || result.Status == store.Unknown {
		for _, id := range p.OperationIDs() {
			b.operations[id] = key
		}
	}
	if result.Status == store.Unknown {
		b.stopped = true
	}
	return RepositoryPostingResult{result, key}
}

func (b *postingBoard) reserve(now time.Time) (uint64, error) {
	var water struct {
		Last domain.U64 `json:"last_reserved_key"`
	}
	if e := strictjson.Decode(b.control.State().Rows["key_watermark:thread"].Value, &water); e != nil {
		return 0, e
	}
	key, e := store.NextThreadKey(uint64(water.Last), now.Unix())
	if e != nil {
		return 0, e
	}
	water.Last = domain.U64(key)
	if e = appendControl(b.control, "key_reservation", []store.Mutation{mutation("key_watermark", "thread", water, nil)}, []string{fmt.Sprint(key)}); e != nil {
		b.stopped = true
		return 0, e
	}
	b.checkpoint("reservation")
	return key, nil
}

func (b *postingBoard) journal(now time.Time) (*evidence.Journal, error) {
	day, e := strconv.ParseUint(now.UTC().Format("20060102"), 10, 64)
	if e != nil {
		return nil, e
	}
	if j := b.journals[day]; j != nil {
		return j, nil
	}
	if e = ensurePostingDirectory(b.evidenceDir); e != nil {
		return nil, e
	}
	j, e := evidence.OpenJournal(filepath.Join(b.evidenceDir, fmt.Sprint(day)), b.owner, day, 10, b.key, b.postingValidator())
	if e != nil {
		return nil, e
	}
	b.journals[day] = j
	return j, nil
}
func (b *postingBoard) close() error {
	var errs []error
	if b.expiryCancel != nil {
		b.expiryCancel()
		<-b.expiryDone
	}
	if b.worker != nil {
		errs = append(errs, b.worker.CloseWithFinalizer(func() error {
			// 有効な送信を先に閉じ、送信側の期限ラッチをwriter終了前に保存する。
			for _, p := range b.threads {
				p.BlockPublic(true)
			}
			if !b.stopped && b.retentionEnabled {
				_, e := b.scanExpiry(true)
				return e
			}
			return nil
		}))
	}
	b.expiryCancel = nil
	for _, p := range b.threads {
		errs = append(errs, p.Close())
	}
	if b.sharedThreadWAL != nil {
		errs = append(errs, b.sharedThreadWAL.Close())
	}
	for _, d := range b.deletions {
		errs = append(errs, d.Close())
	}
	for _, j := range b.journals {
		errs = append(errs, j.Close())
	}
	if b.requiredHolds != nil {
		errs = append(errs, b.requiredHolds.Close())
		b.requiredHolds = nil
	}
	clear(b.key)
	clear(b.dedupKey[:])
	clear(b.publicKey[:])
	clear(b.slipNetKey[:])
	clear(b.slipUAKey[:])
	clear(b.confirmKey[:])
	clear(b.csrfKey[:])
	clear(b.capKey[:])
	return errors.Join(errs...)
}
