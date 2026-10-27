// 非必須HTTPログの起動状態、署名保存、容量予約、周期回収と停止を接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type optionalLogActivation struct {
	Schema string    `json:"schema"`
	Site   domain.ID `json:"site_id"`
	Phase  string    `json:"phase"`
}

// validateOptionalLogActivation は所有者固定のpreparing→activeだけを許可する。
func validateOptionalLogActivation(key string, old, next json.RawMessage) error {
	var v optionalLogActivation
	if key != "http" || strictjson.Decode(next, &v) != nil || v.Schema != "optional-http-activation-v1" || v.Site == (domain.ID{}) || v.Phase != "preparing" && v.Phase != "active" {
		return store.ErrCorrupt
	}
	if len(old) == 0 {
		if v.Phase != "preparing" {
			return store.ErrCorrupt
		}
		return nil
	}
	var prior optionalLogActivation
	if strictjson.Decode(old, &prior) != nil || prior.Site != v.Site || prior.Schema != v.Schema || prior.Phase != "preparing" || v.Phase != "active" {
		return store.ErrCorrupt
	}
	return nil
}

// inspectOptionalLogs は製品checkの読取り検査と、起動時の既知intent補完を区別する。
func inspectOptionalLogs(cfg Config, site siteState, state store.ControlState, allowPending bool) error {
	root := filepath.Join(cfg.DataDir, "reports")
	requiredEntries, e := requiredHoldReportEntries(cfg.DataDir, state)
	if e != nil {
		return e
	}
	row, enabled := state.Rows["optional_http:http"]
	if !enabled {
		return requireReportEntries(root, requiredEntries)
	}
	var activation optionalLogActivation
	if strictjson.Decode(row.Value, &activation) != nil || activation.Site != site.ID || site.MinimumReader < 39 {
		return store.ErrCorrupt
	}
	handled, e := inspectOptionalPreparingRoot(root, activation, requiredEntries, allowPending)
	if handled || e != nil {
		return e
	}
	allowed := append(requiredEntries, "http")
	if _, enabled := state.Rows["optional_loss:http"]; enabled {
		if _, err := os.Lstat(filepath.Join(root, optionalLossDir)); err == nil {
			allowed = append(allowed, optionalLossDir)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if e = requireEntries(root, allowed); e != nil {
		return e
	}
	path := filepath.Join(root, "http")
	if e = privatePath(path, true); e != nil {
		return e
	}
	if _, e := os.Lstat(filepath.Join(path, backupOptionalOmissionName)); e == nil {
		return errors.New("ordinary backup excluded HTTP logs; restore requires independent log history")
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := inspectOptionalHoldActivation(cfg, site, state, allowPending); e != nil {
		return e
	}
	if _, err := os.Lstat(filepath.Join(path, evidence.OptionalHoldsDirectory)); err == nil {
		if site.MinimumReader < 42 {
			return errors.New("HTTP source reservations require reader42")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if activation.Phase == "preparing" && !allowPending {
		return store.ErrIncomplete
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	if e = inspectOptionalLossLogs(cfg, site, state, allowPending, key); e != nil {
		return e
	}
	check, e := optionalHoldStartupCheck(cfg.DataDir, key, site.MinimumReader, allowPending, state)
	if e != nil {
		return e
	}
	if !allowPending {
		return inspectOptionalSourceChecked(path, site, key, state, time.Now(), check)
	}
	s, e := openOptionalSourceChecked(path, site, key, state, check)
	if e != nil {
		return e
	}
	return s.Close()
}

// inspectOptionalPreparingRoot は他の既知reports領域があってもHTTPの準備中欠落を区別する。
func inspectOptionalPreparingRoot(root string, a optionalLogActivation, known []string, allowPending bool) (bool, error) {
	if a.Phase != "preparing" {
		return false, nil
	}
	_, e := os.Lstat(filepath.Join(root, "http"))
	if e == nil {
		return false, nil
	}
	if !os.IsNotExist(e) {
		return true, e
	}
	if e = requireReportEntries(root, known); e != nil {
		return true, e
	}
	if !allowPending {
		return true, store.ErrIncomplete
	}
	return true, nil
}

// ensureOptionalLogs はsite所有mutexの下でreader/作成intentを先に確定し、記録workerを起動する。
func (r *Repository) ensureOptionalLogs() error {
	if r.optionalQueue != nil {
		return nil
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	row, enabled := r.site.State().Rows["optional_http:http"]
	activation := optionalLogActivation{Schema: "optional-http-activation-v1", Site: site.ID, Phase: "preparing"}
	if enabled {
		if e := strictjson.Decode(row.Value, &activation); e != nil {
			return e
		}
	} else {
		requiredEntries, e := requiredHoldReportEntries(r.cfg.DataDir, r.site.State())
		if e != nil {
			return e
		}
		if e := requireReportEntries(filepath.Join(r.cfg.DataDir, "reports"), requiredEntries); e != nil {
			return e
		}
		site.MinimumReader = max(site.MinimumReader, 39)
		if e := appendControl(r.site, "optional_http_prepare", []store.Mutation{mutation("site", "state", site, nil), mutation("optional_http", "http", activation, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	root := filepath.Join(r.cfg.DataDir, "reports", "http")
	if activation.Phase == "preparing" {
		if e := os.Mkdir(root, 0700); e != nil && !os.IsExist(e) {
			return e
		}
		if e := privatePath(root, true); e != nil {
			return e
		}
		if e := store.SyncDirectory(filepath.Dir(root)); e != nil {
			return e
		}
		activation.Phase = "active"
		if e := appendControl(r.site, "optional_http_activate", []store.Mutation{mutation("optional_http", "http", activation, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	seed, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	cases, e := r.evidenceCases.Cases()
	if e != nil {
		return e
	}
	check, e := r.checkedOptionalHoldCases(cases, time.Now())
	if e != nil {
		return e
	}
	s, e := openOptionalSourceChecked(root, site, key, r.site.State(), check)
	if e != nil {
		return e
	}
	r.optionalStore = s
	if e = r.resumeOptionalHoldStorage(s); e != nil {
		s.Close()
		return e
	}
	if e = r.prepareOptionalLoss(site, key); e != nil {
		s.Close()
		return e
	}
	r.snapshotOptionalLossLocked(false)
	var q *evidence.OptionalQueue
	q, e = evidence.NewOptionalBatchQueue(func(ctx context.Context, records []evidence.OptionalRecord) []error {
		failed := func(e error) []error {
			result := make([]error, len(records))
			for i := range result {
				result[i] = e
			}
			return result
		}
		amount, e := evidence.OptionalBatchReservation(records)
		if e != nil {
			return failed(e)
		}
		releaseIO, e := r.postingIO.beginOptionalWithPressure(ctx, q.BacklogPressure, q.BacklogSignal())
		if e != nil {
			return failed(e)
		}
		defer releaseIO()
		release, e := r.reservePrivateLogBytes(uint64(amount))
		if e != nil {
			return failed(e)
		}
		defer release()
		return s.WriteBatch(ctx, records)
	})
	if e != nil {
		s.Close()
		return e
	}
	r.optionalStore = s
	r.optionalQueue = q
	ctx, cancel := context.WithCancel(context.Background())
	r.optionalCancel = cancel
	r.optionalDone = make(chan struct{})
	done := r.optionalDone
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		r.runOptionalLogMaintenance(ctx, s, ticker.C, done)
	}()
	// 署名済み終端の後処理を先行し、参照保存/解除が不明なら原本回収を進めない。
	if e = r.reconcilePendingOptionalExtensionsLocked(context.Background()); e == nil {
		e = r.reconcileTerminalOptionalHoldsLocked(context.Background())
	}
	if e != nil {
		r.optionalCleanupFailed.Store(true)
	} else {
		r.mu.Unlock()
		r.sweepOptionalLogs(s)
		r.mu.Lock()
	}
	return r.available()
}

// runOptionalLogMaintenance は回収と集計snapshotを同じ巡回で実行し、取消後にdoneを閉じる。
func (r *Repository) runOptionalLogMaintenance(ctx context.Context, s *evidence.OptionalStore, ticks <-chan time.Time, done chan struct{}) {
	defer close(done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if e := r.reconcileOptionalRetention(ctx); e != nil {
				r.optionalCleanupFailed.Store(true)
			} else {
				r.sweepOptionalLogs(s)
			}
			r.snapshotOptionalLoss()
		}
	}
}

// openOptionalLogs は有効化済みの固定領域だけを起動し、未導入時は作成しない。
func (r *Repository) openOptionalLogs() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.site.State().Rows["optional_http:http"]; !ok {
		return nil
	}
	return r.ensureOptionalLogs()
}

// sweepOptionalLogs は日別に必要な回収枠だけを予約し、投稿の容量停止中も期限回収を進める。
func (r *Repository) sweepOptionalLogs(s *evidence.OptionalStore) {
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	if r.closed || r.optionalStore != s {
		r.mu.Unlock()
		return
	}
	cases, e := r.evidenceCases.Cases()
	var check func(evidence.OptionalHoldReferences) error
	if e == nil {
		check, e = r.checkedOptionalHoldCases(cases, time.Now())
	}
	r.mu.Unlock()
	if e == nil {
		_, e = s.SweepReservedChecked(time.Now(), func(bytes int64) (func(), error) { return r.reservePrivateReclaimBytes(uint64(bytes)) }, check)
	}
	r.optionalCleanupFailed.Store(e != nil)
}

// closeOptionalLogs は受付と周期処理を止め、保存workerがfileを使わなくなってから閉じる。
// 呼出元はr.muを保持する。周期処理の終了待ち中だけ解放し、戻る前に再取得する。
func (r *Repository) closeOptionalLogs() error {
	if r.optionalQueue == nil {
		return nil
	}
	r.optionalCancel()
	r.mu.Unlock()
	<-r.optionalDone
	r.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	e := r.optionalQueue.Close(ctx)
	// Sync中のcallbackもroot lock解放前に完了させる。
	<-r.optionalQueue.Done()
	r.snapshotOptionalLossLocked(true)
	r.optionalLossMu.Lock()
	if r.optionalLoss != nil {
		r.optionalLoss.Close()
	}
	r.optionalLossMu.Unlock()
	var lossErr error
	if r.optionalLossFailed {
		lossErr = ErrOptionalLossPersistence
	}
	return errors.Join(e, r.optionalStore.Close(), lossErr)
}

// OptionalLogStatus は本人情報を含まない起動後集計。欠測数は保存成功へ読み替えない。
type OptionalLogStatus struct {
	Active           bool                    `json:"active"`
	CleanupFailed    bool                    `json:"cleanup_failed"`
	StartupDiscarded uint64                  `json:"startup_discarded"`
	Queue            evidence.OptionalStatus `json:"queue"`
	Loss             OptionalLossStatus      `json:"loss"`
}

// OptionalHTTPLogs はIP・UA・自由文errorを含めず、保存/欠測/回収失敗の集計を返す。
func (r *Repository) OptionalHTTPLogs() OptionalLogStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	status := OptionalLogStatus{Active: r.optionalQueue != nil && !r.closed, CleanupFailed: r.optionalCleanupFailed.Load()}
	if r.optionalQueue != nil {
		status.Queue = r.optionalQueue.Status()
		status.StartupDiscarded = r.optionalStore.StartupDiscarded()
		status.Loss = r.optionalLossStatusLocked()
	}
	return status
}

// classifyOptionalHTTP は固定enumだけを返し、URL/query自体を記録しない。
func classifyOptionalHTTP(r *http.Request) string {
	path := r.URL.Path
	switch {
	case path == "/test/bbs.cgi" && r.Method == http.MethodPost:
		return "legacy_post"
	case path == "/web/post" && r.Method == http.MethodPost:
		return "web_post"
	case path == "/":
		return "home"
	case path == "/search":
		return "search"
	case path == "/bbsmenu.html" || path == "/bbsmenu.json":
		return "bbsmenu"
	case strings.HasPrefix(path, "/web/assets/"):
		return "asset"
	case strings.HasSuffix(path, "/SETTING.TXT"):
		return "settings"
	case strings.Contains(path, "/dat/") && strings.HasSuffix(path, ".dat"):
		return "dat"
	case strings.HasPrefix(path, "/test/read.cgi/"):
		return "thread"
	case path == "/web/post" || strings.HasSuffix(path, "/") || strings.HasSuffix(path, "/index.html") || strings.HasSuffix(path, "/subback.html") || strings.HasSuffix(path, "/subject.txt"):
		return "board"
	default:
		return "other"
	}
}
