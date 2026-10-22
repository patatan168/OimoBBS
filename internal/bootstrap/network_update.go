// 共通分類をバックグラウンドで取得し、耐久保存後だけ各板へ不変索引を配布する。
package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

// startNetworkUpdater は保存済みの有効な設定で取得する。起動直後は前回成功表を先に配布する。
func (r *Repository) startNetworkUpdater() error {
	v, e := loadNetworkState(r.site.State())
	if e != nil {
		return e
	}
	classifier, e := compileNetworkState(v)
	if e != nil {
		return e
	}
	r.networkHosts.ConfigureDNS(v.Config.DNSMode)
	classifier.Services = r.networkHosts
	r.liveNetworks.Store(classifier)
	if r.captureValidator == nil {
		return nil
	}
	r.networkClient = newNetworkClient()
	ctx, cancel := context.WithCancel(context.Background())
	r.networkCancel = cancel
	r.networkWake = make(chan struct{}, 1)
	r.networkDone = make(chan struct{})
	go func() {
		defer close(r.networkDone)
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			_ = r.refreshNetworks(ctx, r.networkForce.Swap(false))
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			case <-r.networkWake:
			}
		}
	}()
	return nil
}

// wakeNetworkUpdater は取得待ちを通知する。HTTP要求内で外部取得を待たない。
func (r *Repository) wakeNetworkUpdater(force bool) {
	if force {
		r.networkForce.Store(true)
	}
	select {
	case r.networkWake <- struct{}{}:
	default:
	}
}

// refreshNetworks は取得中に管理設定が変わった結果を捨て、失敗では前回表を維持する。
func (r *Repository) refreshNetworks(ctx context.Context, force bool) error {
	r.networkUpdateMu.Lock()
	defer r.networkUpdateMu.Unlock()
	r.mu.Lock()
	if e := r.available(); e != nil {
		r.mu.Unlock()
		return e
	}
	// Stateは不変。大きな分類表の展開・検証中に管理要求のmutexを占有しない。
	snapshot := r.site.State()
	client := r.networkClient
	r.mu.Unlock()
	old, e := loadNetworkState(snapshot)
	if e != nil {
		return e
	}
	if len(old.Config.Sources) == 0 || !force && !old.Config.Enabled {
		return nil
	}
	now := time.Now()
	if !force && old.AttemptVersion == old.Version && old.LastAttempt != 0 {
		interval := time.Duration(old.Config.IntervalHours) * time.Hour
		if old.Error != "" {
			interval = time.Hour
		}
		if now.UnixNano() < int64(old.LastAttempt) || now.Sub(time.Unix(0, int64(old.LastAttempt))) < interval {
			return nil
		}
	}
	r.networkRunning.Store(true)
	defer r.networkRunning.Store(false)
	fetchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	rows, fetchErr := fetchNetworkRows(fetchCtx, client, old.Config.Sources)
	var accessData *networkAccessData
	if fetchErr == nil {
		accessData, fetchErr = fetchAccessData(fetchCtx, client, old.Config.Sources)
	}
	if fetchErr == nil {
		candidate := old
		candidate.Rows = rows
		candidate.AccessData = accessData
		raw, marshalErr := json.Marshal(candidate)
		// 制御frameの包みと管理receiptに余白を確保し、容量超過を取得失敗として扱う。
		if marshalErr != nil || len(raw) > strictjson.MaxBytes-(128<<10) {
			fetchErr = errNetworkData
		}
	}
	cancel()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e = r.available(); e != nil {
		return e
	}
	if r.site.State().Rows["network:active"].Revision != snapshot.Rows["network:active"].Revision {
		return nil
	}
	// 同じ耐久行なら取得開始時に検証した状態を再利用できる。
	current := old
	completed := domain.Time(time.Now().UnixNano())
	if completed < current.LastAttempt {
		return ErrControlExpiryClock
	}
	next := current
	next.LastAttempt = completed
	next.AttemptVersion = current.Version
	next.Error = ""
	if fetchErr != nil {
		next.Error = "fetch_failed"
		if errors.Is(fetchErr, errNetworkData) {
			next.Error = "invalid_data"
		}
	} else {
		next.Rows = rows
		next.AccessData = accessData
		next.LastSuccess = completed
		next.AppliedVersion = current.Version
	}
	if next.validate() != nil {
		return store.ErrCorrupt
	}
	if fetchErr != nil {
		if e = appendControl(r.site, "network_fetch_failed", []store.Mutation{mutation("network", "active", next, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
		return fetchErr
	}
	return r.publishNetworks(next, nil, "network_refresh", nil)
}

// publishNetworks は所有列の先行投稿を排出し、Syncと配布を一つの変更境界にする。site mutex必須。
func (r *Repository) publishNetworks(next networkState, extra []store.Mutation, reason string, actor *domain.Actor) error {
	classifier, e := compileNetworkState(next)
	if e != nil {
		return e
	}
	if _, e = r.freezeCapBoards(domain.ID{}); e != nil {
		return e
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		r.stopped = true
		return e
	}
	site.MinimumReader = max(site.MinimumReader, 70)
	if networkRequiresCountryConflictsReader(next) {
		site.MinimumReader = max(site.MinimumReader, countryConflictsReader)
	}
	if networkRequiresSpecialReader(next) {
		site.MinimumReader = max(site.MinimumReader, specialNetworkReader)
	}
	if networkRequiresMixedReader(next) {
		site.MinimumReader = max(site.MinimumReader, mixedNetworkReader)
	}
	if networkRequiresReader81(next) || len(next.Rows) > networkPackedThreshold {
		site.MinimumReader = max(site.MinimumReader, 81)
	}
	if next.Config.DNSMode != "" {
		site.MinimumReader = max(site.MinimumReader, 37)
	}
	if networkRequiresReader32(next) {
		site.MinimumReader = max(site.MinimumReader, 32)
	}
	if networkRequiresReader33(next) {
		site.MinimumReader = max(site.MinimumReader, 33)
	}
	changes := append([]store.Mutation{mutation("site", "state", site, nil), mutation("network", "active", next, nil)}, extra...)
	id := domain.NewID()
	var actors []domain.Actor
	if actor != nil {
		actors = append(actors, *actor)
	}
	raw, e := controlFrame(r.site.State(), id, domain.Time(time.Now().UnixNano()), reason, changes, []string{}, actors...)
	if e != nil {
		r.resumeAnonymousBoards()
		return e
	}
	result := r.site.Append(raw)
	if result.Status != store.Durable {
		r.stopped = true
		return &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: id}
	}
	r.networkHosts.ConfigureDNS(next.Config.DNSMode)
	classifier.Services = r.networkHosts
	r.liveNetworks.Store(classifier)
	r.resumeAnonymousBoards()
	if r.stopped {
		return ErrPostingUnavailable
	}
	return nil
}
