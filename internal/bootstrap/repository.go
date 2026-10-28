// サイト排他を所有し、板作成の永続intent・板control・公開directoryを順に確定する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/compat"
	"oimobbs/internal/delivery"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/platform"
	"oimobbs/internal/securitylog"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/waf"
)

// Repository はサイト管理・板workerの所有者。Closeまでdata dirの排他を保持する。
// 公開受付は起動ゲートを通った別サーバーが管理し、未知/未検証データは開かない。
type Repository struct {
	pressureEnabled              atomic.Bool
	pressureStatus               atomic.Pointer[StoragePressureStatus]
	pressureMu                   sync.Mutex
	pressureCursor               requiredGCState
	liveWAF                      atomic.Pointer[WAFSettings]
	publicTraffic                waf.TrafficGuard
	adminTraffic                 waf.TrafficGuard
	wafBlocked                   atomic.Uint64
	securityLog                  *securitylog.Log
	guard                        *abuseGuard
	postingIO                    postingIOPriority
	liveSlipEnabled              atomic.Bool
	liveOperations               atomic.Pointer[operationState]
	liveReading                  atomic.Pointer[readingSnapshot]
	liveReadingBoards            atomic.Pointer[readingBoardIndex]
	maintenanceWake              chan struct{}
	reportMu                     sync.Mutex
	autoReportBoard              domain.ID
	autoReportVotes              map[autoReportTarget][]autoReportVote
	optionalStore                *evidence.OptionalStore
	optionalLoss                 *evidence.OptionalLossStore
	optionalLossMu               sync.Mutex
	optionalLossSite             domain.ID
	optionalLossBeforeSnapshot   func()
	optionalHoldBeforeInitialize func()
	optionalHoldBeforeReserve    func()
	optionalHoldAfterReserve     func()
	requiredHoldBeforeReserve    func()
	requiredHoldAfterReserve     func()
	requiredExtensionAfterRenew  func()
	optionalLossStarted          time.Time
	optionalLossBoot             domain.ID
	optionalLossFailed           bool
	optionalQueue                *evidence.OptionalQueue
	optionalCancel               context.CancelFunc
	optionalDone                 chan struct{}
	optionalCleanupFailed        atomic.Bool
	evidenceCases                *disclosure.Store
	evidenceCancel               context.CancelFunc
	evidenceDone                 chan struct{}
	evidenceCleanupFailed        bool
	networkHosts                 *identity.HostCache
	feedCompression              *compat.CompressionCache
	networkRunning               atomic.Bool
	networkViewCache             *networkView // muで保護。耐久行の版が変わった時だけ再集計する。
	liveNetworks                 atomic.Pointer[identity.NetworkClassifier]
	networkClient                *http.Client
	networkCancel                context.CancelFunc
	networkWake                  chan struct{}
	networkDone                  chan struct{}
	networkForce                 atomic.Bool
	networkUpdateMu              sync.Mutex
	controlExpiryFloor           atomic.Int64
	egress                       *delivery.Scheduler
	publicRevision               atomic.Uint64
	searchReserved               atomic.Int64
	memory                       atomic.Pointer[platform.MemoryState]
	memoryReserved               atomic.Uint64
	memoryRejected               atomic.Uint64
	searchOnce                   sync.Once
	searchWorkers                chan struct{}
	searchRequests               chan struct{}
	onlineCatalog                *onlineCatalog
	backupReserved               uint64
	backupActive                 bool
	postingLatencyMu             sync.Mutex
	postingLatency               postingLatencyState
	latencyClock                 func() time.Time
	postReserved                 uint64
	postBodyReserved             uint64
	postingCapacity              postingCapacityState
	capacityClock                func() time.Time
	packResourcesMu              sync.Mutex
	packReserved                 uint64
	packSpace                    func(string) (platform.DiskSpace, error)
	maintenanceClock             func() time.Time
	maintenanceMu                sync.Mutex
	maintenanceStatusMu          sync.Mutex
	maintenanceStatus            PackMaintenanceStatus
	anchors                      map[domain.ID]candidateOwner
	auditSnapshots               map[string]auditSnapshot
	auditIndex                   *auditIndex
	denialCount                  int
	reportRates                  map[string]reportRateWindow
	adminAuth                    *adminauth.Manager
	mu                           sync.RWMutex
	optionalHoldLifecycleMu      sync.Mutex
	optionalExtensionAfterRenew  func()
	cfg                          Config
	lock                         *os.File
	site                         *store.ControlLog
	boards                       map[domain.ID]*store.ControlLog
	closed, stopped              bool
	checkpoint                   func(string)
	captureValidator             func([]byte) error
	parallelCaptureValidation    bool
	requiredHoldsOmitted         bool
	posting                      map[domain.ID]*postingBoard
	admission                    *admission
	anonymous                    *anonymousState
	liveConsent                  atomic.Pointer[postingConsentState]
	liveAnonymous                atomic.Pointer[anonymousState]
	bot                          botGuard
	liveCaps                     atomic.Pointer[capRegistry]
}

// OpenRepository は全体を読取り検査してから、保存済み作成intentを同じIDで再開する。
func OpenRepository(cfg Config) (*Repository, error) { return openRepository(cfg, func(string) {}) }
func openRepository(cfg Config, checkpoint func(string)) (*Repository, error) {
	return openPostingRepository(cfg, checkpoint, nil)
}
func openPostingRepository(cfg Config, checkpoint func(string), captureValidator func([]byte) error, options ...PostingOptions) (*Repository, error) {
	if len(options) > 1 {
		return nil, errors.New("at most one posting options value")
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.checkTLS(time.Now()); err != nil {
		return nil, err
	}
	if err := privatePath(cfg.DataDir, true); err != nil {
		return nil, err
	}
	if err := privatePath(filepath.Join(cfg.DataDir, ".lock"), false); err != nil {
		return nil, err
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	return openLockedPostingRepository(cfg, lock, checkpoint, captureValidator, "", options...)
}

// openLockedPostingRepository は取得済みlockの所有権を引き取り、失敗時も必ず解放する。
func openLockedPostingRepository(cfg Config, lock *os.File, checkpoint func(string), captureValidator func([]byte) error, intent string, options ...PostingOptions) (*Repository, error) {
	repo := &Repository{maintenanceWake: make(chan struct{}, 1), networkHosts: identity.NewHostCache(nil), cfg: cfg, lock: lock, boards: map[domain.ID]*store.ControlLog{}, checkpoint: checkpoint, captureValidator: captureValidator, posting: map[domain.ID]*postingBoard{}}
	repo.parallelCaptureValidation = len(options) == 1 && options[0].ParallelCaptureValidation
	repo.refreshMemory()
	repo.feedCompression = compat.NewCompressionCache(0, 1)
	repo.feedCompression.SetResources(repo.representationResources)
	repo.feedCompression.SetAdmission(func() (func(), bool) { return repo.reserveMemory(representationWorkerBytes) })
	ok := false
	defer func() {
		if !ok {
			_ = repo.Close()
		}
	}()
	report, err := checkLockedPostingIntent(cfg, true, captureValidator != nil, intent)
	if err != nil {
		return nil, err
	}
	repo.site, err = store.OpenControlWithValidators(filepath.Join(cfg.DataDir, "site"), 1, report.SiteID, 0, validateSiteValue, snapshotSiteValue)
	if err != nil {
		return nil, err
	}
	var consentSite siteState
	if err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &consentSite); err != nil {
		return nil, err
	}
	repo.liveConsent.Store(newPostingConsentState(consentSite))
	reading, err := loadReadingSnapshot(repo.site.State())
	if err != nil {
		return nil, err
	}
	repo.liveReading.Store(reading)
	policy := repo.wafSettings()
	if row, ok := repo.site.State().Rows["waf:active"]; ok {
		if err = strictjson.Decode(row.Value, &policy); err != nil {
			return nil, err
		}
	}
	repo.publishWAF(policy)

	if row, ok := repo.site.State().Rows["operations:active"]; ok {
		var settings operationState
		if err = strictjson.Decode(row.Value, &settings); err != nil {
			return nil, err
		}
		repo.liveOperations.Store(&settings)
		repo.feedCompression.RefreshResources()
	}
	if row, ok := repo.site.State().Rows["expiry_watermark:control"]; ok {
		var floor controlExpiryWatermark
		if err = strictjson.Decode(row.Value, &floor); err != nil {
			return nil, err
		}
		repo.controlExpiryFloor.Store(int64(floor.At))
	}
	entries, err := inspectBoardsMode(cfg, repo.site.State(), true, captureValidator != nil)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.directory == nil || entry.directory.Status != "active" || entry.job.State != "completed" {
			if _, err = repo.resumeBoard(entry.job); err != nil {
				return nil, err
			}
		} else {
			log, err := store.OpenControlWithValidators(filepath.Join(cfg.DataDir, "boards", entry.info.ID.String(), "control"), 2, entry.info.ID, 0, validateBoardValue, snapshotBoardValue)
			if err != nil {
				return nil, err
			}
			repo.boards[entry.info.ID] = log
		}
	}
	if err = repo.loadControlAnchors(); err != nil {
		return nil, err
	}
	if _, err = repo.administrators(); err != nil {
		return nil, err
	}
	reg, err := loadCapRegistry(repo.site.State())
	if err != nil {
		return nil, err
	}
	repo.liveCaps.Store(reg)
	if err = repo.loadAdmission(); err != nil {
		return nil, err
	}
	if err = repo.loadAnonymous(); err != nil {
		return nil, err
	}
	if err = repo.loadSlipPolicy(); err != nil {
		return nil, err
	}
	repo.securityLog, err = securitylog.Open(filepath.Join(cfg.DataDir, "security-events"))
	if err != nil {
		return nil, err
	}
	repo.guard = &abuseGuard{settings: defaultAbuseGuard(), log: repo.securityLog}
	repo.publishGlobalRules(repo.globalRulesViewLocked().Settings)
	if captureValidator != nil {
		if err = repo.openPostings(); err != nil {
			return nil, err
		}
	}
	if err = repo.restoreViolations(); err != nil {
		return nil, err
	}
	if err = repo.restoreAbuseGuard(); err != nil {
		return nil, err
	}
	if err = repo.restoreAdmission(); err != nil {
		return nil, err
	}
	if captureValidator != nil {
		if err = repo.restoreAutoReports(); err != nil {
			return nil, err
		}
	}
	if err = repo.openEvidenceCases(); err != nil {
		return nil, err
	}
	if _, enabled := repo.site.State().Rows["report_store:active"]; enabled {
		if err = repo.ensureReports(); err != nil {
			return nil, err
		}
		if err = repo.cleanReportPending(); err != nil {
			return nil, err
		}
	}
	if err = repo.openOptionalLogs(); err != nil {
		return nil, err
	}
	if err = repo.loadOnlineCatalog(); err != nil {
		return nil, err
	}
	if err = repo.startNetworkUpdater(); err != nil {
		return nil, err
	}
	repo.startEvidenceCleanup()
	// 復旧で保持した状態量を受付前に反映し、起動前の空き量を使い続けない。
	repo.refreshMemory()
	ok = true
	return repo, nil
}

// Close はすべての所有fileを閉じた後にロックを解放する。複数回呼出し可能。
func (r *Repository) Close() error {
	r.mu.Lock()
	defer func() {
		r.mu.Unlock()
		if r.evidenceDone != nil {
			<-r.evidenceDone
		}
		if r.networkDone != nil {
			<-r.networkDone
		}
	}()
	if r.closed {
		return nil
	}
	r.closed = true
	if r.networkHosts != nil {
		r.networkHosts.Close()
	}
	if r.networkCancel != nil {
		r.networkCancel()
	}
	if r.networkClient != nil {
		r.networkClient.CloseIdleConnections()
	}
	if r.egress != nil {
		r.egress.Close()
	}
	if r.evidenceCancel != nil {
		r.evidenceCancel()
	}
	var errs []error
	errs = append(errs, r.closeOptionalLogs())
	if r.evidenceCases != nil {
		errs = append(errs, r.evidenceCases.Close())
	}
	for _, b := range r.posting {
		errs = append(errs, b.close())
	}
	errs = append(errs, r.securityLog.Close())
	for _, log := range r.boards {
		errs = append(errs, log.Close())
	}
	if r.site != nil {
		errs = append(errs, r.site.Close())
	}
	if r.lock != nil {
		errs = append(errs, platform.Unlock(r.lock))
	}
	return errors.Join(errs...)
}
func (r *Repository) available() error {
	if time.Now().UnixNano() < r.controlExpiryFloor.Load() {
		return ErrControlExpiryClock
	}
	if r.closed {
		return errors.New("repository closed")
	}
	if r.stopped {
		return errors.New("repository writer stopped; reopen for recovery")
	}
	return nil
}

// Boards は確定済みactive板だけの管理一覧を返す。保存用の設定・jobは露出しない。
func (r *Repository) Boards() ([]BoardInfo, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return nil, err
	}
	entries, err := inspectBoardsMode(r.cfg, r.site.State(), false, r.captureValidator != nil)
	if err != nil {
		return nil, err
	}
	rows := make([]BoardInfo, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, entry.info)
	}
	return rows, nil
}

// CreateBoard はOSの保存所有者による停止中の板作成。公開の利用者から呼び出さない。
// 同じkey/nameの再実行は同じ板を返し、異なる内容は保存せず拒否する。
func (r *Repository) CreateBoard(ctx context.Context, key, name string) (info BoardInfo, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.createBoardLocked(ctx, key, name, nil)
}

// createBoardLocked は既存の復旧可能な作成経路を管理画面とCLIで共有する。呼出元がsiteロックを保持する。
func (r *Repository) createBoardLocked(ctx context.Context, key, name string, owner *domain.ID) (info BoardInfo, err error) {
	return r.createBoardWithPolicyLocked(ctx, key, name, owner, "")
}

// createBoardWithPolicyLocked は投稿方式を初期jobへ保存してから板を公開する。空のpolicyは従来のCLI作成。
func (r *Repository) createBoardWithPolicyLocked(ctx context.Context, key, name string, owner *domain.ID, policy string) (info BoardInfo, err error) {
	if err = r.available(); err != nil {
		return info, err
	}
	if err = ctx.Err(); err != nil {
		return info, err
	}
	if !validBoardKey(key) || !validName(name) {
		return info, errors.New("invalid board key or name")
	}
	if policy != "" && policy != "anyone" && policy != "cap_only" || policy == "cap_only" && owner == nil {
		return info, errors.New("invalid board creation policy")
	}
	existing, count, err := r.boardProvisionLookup(ctx, key)
	if err != nil {
		return info, err
	}
	if existing.ID != (domain.ID{}) {
		if existing.Key != key || existing.Name != name {
			return info, &adminFailure{status: 409, code: "BOARD_KEY_EXISTS"}
		}
		if policy != "" {
			if err = r.checkBoardCreationPolicy(ctx, existing.ID, policy); err != nil {
				return info, err
			}
		}
		return existing, nil
	}
	if count >= maxPersistentBoards {
		return info, &adminFailure{status: 409, code: "BOARD_LIMIT_REACHED"}
	}
	job, err := r.newJob(key, name, policy)
	if err != nil {
		return info, err
	}
	job.OwnerAdmin = owner
	// ここから先は取消後も保存結果を確定する。どのI/O失敗でも再利用せず復旧へ渡す。
	defer func() {
		if err != nil {
			r.stopped = true
		}
	}()
	if owner != nil {
		var site siteState
		if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
			return info, err
		}
		requiredReader := uint32(63)
		if policy == "cap_only" {
			requiredReader = 73
		}
		if site.MinimumReader < requiredReader {
			site.MinimumReader = requiredReader
			if err = appendControl(r.site, "board_create_reader", []store.Mutation{mutation("site", "state", site, nil)}, []string{site.ID.String()}); err != nil {
				return info, err
			}
		}
	}
	frame, err := controlFrame(store.ControlState{}, job.ID, job.Created, "provision_board", []store.Mutation{mutation("job", job.ID.String(), job, nil)}, []string{job.Parameters.BoardID.String()}, provisionActor(job))
	if err != nil {
		return info, err
	}
	log, err := store.CreateControl(filepath.Join(r.cfg.DataDir, "jobs", job.ID.String()), store.Header{Kind: 6, Owner: job.ID, Generation: 1}, frame, validateProvisionJob)
	if err != nil {
		return info, err
	}
	if err = log.Close(); err != nil {
		return info, err
	}
	r.checkpoint("job")
	info, err = r.resumeBoard(job)
	if err == nil && r.captureValidator != nil {
		err = r.openPostingBoard(info.ID)
	}
	return info, err
}
func (r *Repository) newJob(key, name string, policies ...string) (provisionJob, error) {
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return provisionJob{}, err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return provisionJob{}, err
	}
	id := domain.NewID()
	dirs, err := siteDirectories(r.site.State())
	if err != nil {
		return provisionJob{}, err
	}
	for id == siteID(r.site.State()) || dirs[id] != nil {
		id = domain.NewID()
	}
	now := domain.Time(time.Now().UnixNano())
	policy := "anyone"
	if len(policies) > 0 && policies[0] == "cap_only" {
		policy = "cap_only"
	}
	return provisionJob{ID: domain.NewID(), Kind: "provision_board", State: "running", Boards: []domain.ID{id}, Created: now, Started: &now, Request: boardRequest(secret, key, name, policy), Parameters: boardParameters{BoardID: id, Key: key, Name: name, Settings: initialBoardSettings(policy)}, Totals: provisionTotals{Total: 1, Pending: 1}}, nil
}
func boardRequest(key domain.Hash, slug, name string, policies ...string) domain.Hash {
	if len(policies) > 0 && policies[0] == "cap_only" {
		return identity.MAC(key[:], "oimo/board-provision/v2", []byte(slug), []byte(name), []byte("cap_only"))
	}
	return identity.MAC(key[:], "oimo/board-provision/v1", []byte(slug), []byte(name))
}
func mutation(collection, key string, value any, expires *domain.Time) store.Mutation {
	b, err := json.Marshal(value)
	if err != nil {
		panic("internal control value cannot be encoded")
	}
	return store.Mutation{Collection: collection, Key: key, Value: b, Expires: expires}
}
func controlFrame(state store.ControlState, id domain.ID, now domain.Time, reason string, mutations []store.Mutation, targets []string, actors ...domain.Actor) ([]byte, error) {
	if state.Seq == domain.U64(^uint64(0)) {
		return nil, errors.New("control sequence exhausted")
	}
	for i := range mutations {
		mutations[i].ExpectedRevision = state.Rows[mutations[i].Collection+":"+mutations[i].Key].Revision
	}
	op := store.ControlOperation{Schema: 1, Seq: state.Seq + 1, ExpectedSeq: state.Seq, Committed: now, Actor: domain.Actor{Kind: "system", Reason: reason}, Mutations: mutations, Result: store.ControlResult{Code: reason, Targets: targets}}
	if len(actors) == 1 {
		op.Actor = actors[0]
	}
	raw, err := json.Marshal(op)
	if err != nil {
		return nil, err
	}
	return store.EncodeFrame(store.Frame{FirstSeq: uint64(op.Seq), Records: []store.Record{{ID: id, JSON: raw}}})
}
func appendControl(log *store.ControlLog, reason string, mutations []store.Mutation, targets []string) error {
	frame, err := controlFrame(log.State(), domain.NewID(), domain.Time(time.Now().UnixNano()), reason, mutations, targets)
	if err != nil {
		return err
	}
	result := log.Append(frame)
	if result.Status != store.Durable {
		return fmt.Errorf("control commit not durable: %w", result.Err)
	}
	return nil
}

// ReserveThreadKey はcreate前の高水位を独立してSyncする。取消・失敗で予約を戻さない。
func (r *Repository) ReserveThreadKey(ctx context.Context, id domain.ID, now time.Time) (uint64, error) {
	r.mu.Lock()
	if b := r.posting[id]; b != nil {
		err := r.available()
		r.mu.Unlock()
		if err != nil {
			return 0, err
		}
		value, err := b.worker.Submit(ctx, func() (any, error) {
			if b.stopped {
				return uint64(0), errors.New("board writer stopped")
			}
			return b.reserve(now)
		})
		if err != nil {
			return 0, err
		}
		return value.(uint64), nil
	}

	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	log := r.boards[id]
	if log == nil {
		return 0, errors.New("board not active")
	}
	var water struct {
		Last domain.U64 `json:"last_reserved_key"`
	}
	if err := strictjson.Decode(log.State().Rows["key_watermark:thread"].Value, &water); err != nil {
		return 0, err
	}
	key, err := store.NextThreadKey(uint64(water.Last), now.Unix())
	if err != nil {
		return 0, err
	}
	water.Last = domain.U64(key)
	if err = appendControl(log, "key_reservation", []store.Mutation{mutation("key_watermark", "thread", water, nil)}, []string{fmt.Sprint(key)}); err != nil {
		r.stopped = true
		return 0, err
	}
	r.checkpoint("reservation")
	return key, nil
}
