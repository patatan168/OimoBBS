// 運用設定をサイトcontrolへ保存し、起動設定から独立して稼働中と再起動後に適用する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/delivery"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

// ReportPolicy は新しい通報の集計条件。既存の停止には成立時の条件を保存する。
type ReportPolicy struct {
	WindowSeconds int `json:"window_seconds"`
	Quorum        int `json:"quorum"`
	StopSeconds   int `json:"stop_seconds"`
}

func defaultReportPolicy() ReportPolicy { return ReportPolicy{86400, 3, 600} }
func (p ReportPolicy) valid() bool {
	return p.WindowSeconds%60 == 0 && p.StopSeconds%60 == 0 && p.WindowSeconds >= 60 && p.WindowSeconds <= 604800 && p.Quorum >= 1 && p.Quorum <= 20 && p.StopSeconds >= 60 && p.StopSeconds <= 86400
}
func (p ReportPolicy) window() time.Duration { return time.Duration(p.WindowSeconds) * time.Second }
func (p ReportPolicy) stop() time.Duration   { return time.Duration(p.StopSeconds) * time.Second }
func ruleReportPolicy(r denialRule) ReportPolicy {
	if r.ReportPolicy != nil {
		return *r.ReportPolicy
	}
	return ReportPolicy{}
}

// OperationSettings は署名付き保存記録の運用設定。CacheBytes・CacheWorkersは過去記録の
// 検証にだけ残し、現在の資源計算・管理APIでは使わない。新規保存では常に0にする。
type OperationSettings struct {
	Maintenance           PackMaintenanceConfig `json:"maintenance"`
	EgressBits            uint64                `json:"egress_budget_bits_per_second"`
	CacheBytes            uint64                `json:"cache_bytes"`
	CacheWorkers          int                   `json:"cache_workers"`
	Reports               ReportPolicy          `json:"reports"`
	ReportIntervalMinutes int                   `json:"report_interval_minutes,omitempty"`
}

func (v OperationSettings) valid() bool {
	m := v.Maintenance
	return v.ReportIntervalMinutes >= 0 && v.ReportIntervalMinutes <= 1440 && m.IntervalSeconds >= 60 && m.IntervalSeconds <= 86400 && m.MaxThreads >= 1 && m.MaxThreads <= 1000 && m.MaxSeconds >= 1 && m.MaxSeconds <= 300 && v.EgressBits%1_000_000 == 0 && v.CacheBytes%(1<<20) == 0 && v.EgressBits >= 1_000_000 && v.EgressBits <= delivery.MaxBudgetBits && v.CacheBytes <= 1<<40 && v.CacheWorkers >= 0 && v.CacheWorkers <= 4096 && v.Reports.valid()
}

type operationState struct {
	Settings    OperationSettings `json:"settings"`
	ReportSince domain.Time       `json:"report_since_ns"`
}

// AdminOperations は編集対象と保存版を返す。起動設定の秘密・内部pathは含めない。
type AdminOperations struct {
	Settings    OperationSettings `json:"settings"`
	Revision    domain.U64        `json:"revision"`
	ReportBoard string            `json:"report_board"`
}

func (v AdminOperations) ETag() string { return fmt.Sprintf(`"operations:%d"`, v.Revision) }

type operationsReceipt struct {
	ID      domain.ID       `json:"id"`
	Admin   domain.ID       `json:"admin_id"`
	Key     domain.Hash     `json:"key_hmac"`
	Request domain.Hash     `json:"request_hmac"`
	Result  AdminOperations `json:"result"`
	Created domain.Time     `json:"created_at_ns"`
	Expires domain.Time     `json:"expires_at_ns"`
}

func validateOperationsValue(collection, key string, old, next json.RawMessage) error {
	if collection == "operations" {
		var v operationState
		if key != "active" || strictjson.Decode(next, &v) != nil || !v.Settings.valid() || v.ReportSince <= 0 {
			return store.ErrCorrupt
		}
		if len(old) > 0 {
			var p operationState
			if strictjson.Decode(old, &p) != nil || v.ReportSince < p.ReportSince {
				return store.ErrCorrupt
			}
		}
		return nil
	}
	var v operationsReceipt
	if strictjson.Decode(next, &v) != nil || key != v.Key.String() || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Request == (domain.Hash{}) || v.Key == (domain.Hash{}) || !v.Result.Settings.valid() || v.Result.Revision == 0 || (v.Result.ReportBoard != "" && !validBoardKey(v.Result.ReportBoard)) || v.Created <= 0 || v.Expires-v.Created != 86400e9 {
		return store.ErrCorrupt
	}
	if len(old) > 0 {
		var p operationsReceipt
		if strictjson.Decode(old, &p) != nil || v.Created < p.Expires {
			return store.ErrCorrupt
		}
	}
	return nil
}

// operations は保存値がある場合だけ上書きする。返却値はコピーで、設定変更と競合しない。
func (r *Repository) operations() OperationSettings {
	if v := r.liveOperations.Load(); v != nil {
		settings := v.Settings
		settings.CacheBytes, settings.CacheWorkers = 0, 0
		settings.ReportIntervalMinutes = settings.reportIntervalMinutes()
		return settings
	}
	m := PackMaintenanceConfig{IntervalSeconds: 300, MaxThreads: 5, MaxSeconds: 30}
	if r.cfg.Maintenance != nil {
		m = *r.cfg.Maintenance
		if m.MaxSeconds == 0 {
			m.MaxSeconds = 30
		}
	}
	return OperationSettings{m, r.cfg.EgressBits, 0, 0, defaultReportPolicy(), 10}
}
func (r *Repository) reportSince() domain.Time {
	var at domain.Time
	if r.cfg.AutoReports != nil {
		t, _ := time.Parse(time.RFC3339, r.cfg.AutoReports.Since)
		at = domain.Time(t.UnixNano())
	}
	if v := r.liveOperations.Load(); v != nil {
		at = max(at, v.ReportSince)
	}
	return at
}

// operationsView はサイトmutex所有中に保存版と現在値を取得する。
func (r *Repository) operationsView() AdminOperations {
	board := ""
	if r.cfg.AutoReports != nil {
		board = r.cfg.AutoReports.BoardKey
	}
	return AdminOperations{r.operations(), r.site.State().Rows["operations:active"].Revision, board}
}
func (r *Repository) adminOperations(s adminauth.Session) (AdminOperations, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.currentAdministrator(s); e != nil {
		return AdminOperations{}, e
	}
	return r.operationsView(), nil
}

// updateOperations は再送照会・CAS・操作者付きSyncを経て実行中の共有処理へ反映する。
func (r *Repository) updateOperations(s adminauth.Session, v OperationSettings, etag, key string) (AdminOperations, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.currentAdministrator(s); e != nil {
		return AdminOperations{}, e
	}
	if e := r.available(); e != nil {
		return AdminOperations{}, e
	}
	v.CacheBytes, v.CacheWorkers = 0, 0
	if v.ReportIntervalMinutes == 0 {
		v.ReportIntervalMinutes = r.operations().reportIntervalMinutes()
	}
	if !v.valid() {
		return AdminOperations{}, &adminFailure{status: 422, code: "INVALID_OPERATIONS"}
	}
	if !adminRequestKey.MatchString(key) {
		return AdminOperations{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminOperations{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return AdminOperations{}, e
	}
	defer clear(master)
	secret, e := identity.DeriveKey(master, "dedup", 8)
	if e != nil {
		return AdminOperations{}, e
	}
	requestKey := identity.MAC(secret[:], "oimo/admin-operations-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(v)
	request := identity.MAC(secret[:], "oimo/admin-operations/v1", s.Admin[:], raw, []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	if prior, ok := state.Rows["operations_receipt:"+requestKey.String()]; ok {
		var receipt operationsReceipt
		if e = strictjson.Decode(prior.Value, &receipt); e != nil {
			return AdminOperations{}, e
		}
		if receipt.Created > now {
			return AdminOperations{}, ErrPostingUnavailable
		}
		if receipt.Expires > now {
			if receipt.Request != request {
				return AdminOperations{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return receipt.Result, nil
		}
	}
	current := r.operationsView()
	if current.ETag() != etag {
		return AdminOperations{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "operations_receipt:") {
			count++
		}
	}
	if count >= 200000 {
		return AdminOperations{}, ErrPostingUnavailable
	}
	next := operationState{v, r.reportSince()}
	if next.ReportSince <= 0 || current.Settings.Reports != v.Reports {
		next.ReportSince = now
	}
	result := AdminOperations{v, state.Seq + 1, current.ReportBoard}
	receipt := operationsReceipt{domain.NewID(), s.Admin, requestKey, request, result, now, now + 86400e9}
	var site siteState
	if e = strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		return AdminOperations{}, e
	}
	site.MinimumReader = max(site.MinimumReader, reportIntervalReader)
	if v.EgressBits > 1_000_000_000 {
		site.MinimumReader = max(site.MinimumReader, postingResourcesReader)
	}
	if v.CacheWorkers == 0 || v.CacheWorkers > 8 || v.CacheBytes > 128<<20 {
		site.MinimumReader = max(site.MinimumReader, 89)
	}
	if current.Settings.Reports != v.Reports {
		site.PublicRevision = state.Seq + 1
	}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("operations", "active", next, nil), mutation("operations_receipt", requestKey.String(), receipt, nil)}
	kid := uint32(8)
	frame, e := controlFrame(state, receipt.ID, now, "operations_update", changes, []string{site.ID.String()}, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "operations_update", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if e != nil {
		return AdminOperations{}, e
	}
	if outcome := r.site.Append(frame); outcome.Status != store.Durable {
		r.stopped = true
		return AdminOperations{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
	}
	r.publicRevision.Store(uint64(site.PublicRevision))
	r.liveOperations.Store(&next)
	if current.Settings.Reports != v.Reports {
		r.autoReportVotes = make(map[autoReportTarget][]autoReportVote)
	}
	r.feedCompression.RefreshResources()
	if r.egress != nil {
		if e = r.egress.UpdateBudget(v.EgressBits); e != nil {
			r.stopped = true
			return AdminOperations{}, e
		}
	}
	for _, b := range r.posting {
		if r.cfg.AutoReports == nil {
			continue
		}
		snapshot, err := receiptSnapshotForBoard(r.cfg.Public.BaseURL, b.boardKey(), v.Reports, b.autoReports.Load())
		if err != nil {
			r.stopped = true
			return AdminOperations{}, err
		}
		b.receipt.Store(snapshot)
	}

	select {
	case r.maintenanceWake <- struct{}{}:
	default:
	}
	return result, nil
}

// reportIntervalMinutes は旧保存値の省略を既定の10分として扱う。
func (v OperationSettings) reportIntervalMinutes() int {
	if v.ReportIntervalMinutes == 0 {
		return 10
	}
	return v.ReportIntervalMinutes
}
