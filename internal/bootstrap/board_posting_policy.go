// 板別の投稿間隔設定とCookie優先設定を変更時刻付きで保存し、消費量を維持する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"sort"
	"strings"
	"time"
)

// AdminRateSettings は板単位のIP/token枠。network/siteの過負荷対策は変更しない。
// 無効中も同じキーで履歴を記録し、再有効化で連投履歴を消さない。
type AdminRateSettings struct {
	Enabled       bool   `json:"enabled"`
	ReplySeconds  uint32 `json:"reply_seconds"`
	ReplyBurst    uint32 `json:"reply_burst"`
	CreateSeconds uint32 `json:"create_seconds"`
	CreateBurst   uint32 `json:"create_burst"`
	CreateWindow  uint32 `json:"create_window_limit"`
}

func defaultRateSettings() AdminRateSettings { return AdminRateSettings{true, 1, 3, 600, 1, 6} }
func (v AdminRateSettings) validate() error {
	if v.ReplySeconds < 1 || v.CreateSeconds < 1 || v.ReplyBurst < 1 || v.ReplyBurst > 100 || v.CreateBurst < 1 || v.CreateBurst > 100 || uint64(v.ReplySeconds)*uint64(v.ReplyBurst) > 3600 || uint64(v.CreateSeconds)*uint64(v.CreateBurst) > 3600 || v.CreateWindow < v.CreateBurst || v.CreateWindow > 1000 {
		return abuse.ErrRateSpec
	}
	return nil
}
func (v AdminRateSettings) spec(create bool) abuse.RateSpec {
	s := abuse.RateSpec{Tokens: 1, Every: time.Duration(v.ReplySeconds) * time.Second, Burst: v.ReplyBurst, Disabled: !v.Enabled, TrackWindow: create}
	if create {
		s.Every = time.Duration(v.CreateSeconds) * time.Second
		s.Burst = v.CreateBurst
		s.WindowLimit = v.CreateWindow
	}
	return s
}
func (v AdminBoardEdit) rates() AdminRateSettings {
	if v.Rates == nil {
		return defaultRateSettings()
	}
	return *v.Rates
}

type boardPostingPolicy struct {
	ID    domain.ID         `json:"id"`
	At    domain.Time       `json:"changed_at_ns"`
	Rates AdminRateSettings `json:"rates"`
}

func validateBoardPostingPolicy(key string, old, next []byte) error {
	var p boardPostingPolicy
	if e := strictjson.Decode(next, &p); e != nil {
		return e
	}
	if len(old) != 0 || p.ID == (domain.ID{}) || key != p.ID.String() || p.At <= 0 {
		return store.ErrCorrupt
	}
	return p.Rates.validate()
}
func postingPolicies(state store.ControlState) ([]boardPostingPolicy, error) {
	policies := []boardPostingPolicy{}
	for key, row := range state.Rows {
		if !strings.HasPrefix(key, "posting_policy:") {
			continue
		}
		if row.Expires != nil {
			return nil, store.ErrCorrupt
		}
		var p boardPostingPolicy
		if e := strictjson.Decode(row.Value, &p); e != nil {
			return nil, e
		}
		policies = append(policies, p)
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].At < policies[j].At })
	for i, p := range policies {
		if i > 0 && (p.At <= policies[i-1].At) {
			return nil, store.ErrCorrupt
		}
	}
	if len(policies) > 10000 {
		return nil, store.ErrCorrupt
	}
	return policies, nil
}
func currentPostingPolicy(state store.ControlState) (boardPostingPolicy, error) {
	rows, e := postingPolicies(state)
	if e != nil {
		return boardPostingPolicy{}, e
	}
	if len(rows) == 0 {
		return boardPostingPolicy{Rates: defaultRateSettings()}, nil
	}
	return rows[len(rows)-1], nil
}

// applyBoardRates は板ワーカー境界で使う。変更前の補充後、同じキーへ新条件を適用する。
func (a *admission) applyBoardRates(board domain.ID, v AdminRateSettings, at time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyBoardRatesLocked(board, v, at)
}
func (a *admission) applyBoardRatesLocked(board domain.ID, v AdminRateSettings, at time.Time) error {
	if a.globalRates != nil {
		v = *a.globalRates
	}
	specs := map[string]abuse.RateSpec{}
	for key, create := range a.boardKeys[board] {
		specs[key] = v.spec(create)
	}
	if e := a.limits.Reconfigure(at, specs); e != nil {
		return e
	}
	if a.boardRates == nil {
		a.boardRates = map[domain.ID]AdminRateSettings{}
	}
	a.boardRates[board] = v
	return nil
}
func (a *admission) trackBoardCharges(board domain.ID, create bool, charges []abuse.RateCharge) {
	if a.boardKeys == nil {
		a.boardKeys = map[domain.ID]map[string]bool{}
	}
	if a.boardKeys[board] == nil {
		a.boardKeys[board] = map[string]bool{}
	}
	for _, c := range charges {
		if strings.HasPrefix(c.Key, a.policy.Rules[0].ID.String()+":") || strings.HasPrefix(c.Key, a.policy.Rules[1].ID.String()+":") || a.anonymous != nil && (strings.HasPrefix(c.Key, a.anonymous.ReplyRule.String()+":") || strings.HasPrefix(c.Key, a.anonymous.CreateRule.String()+":")) {
			a.boardKeys[board][c.Key] = create
		}
	}
}

// ensureOnlinePostingPolicies はサイトmutexの下で初回保存と全板の境界を完了する。
// 保存結果が不明なら再開せず、復旧照合に委ねる。既存policyと消費量は変更しない。
func (r *Repository) ensureOnlinePostingPolicies() error {
	if r.admission != nil && r.anonymous != nil {
		return nil
	}
	if r.captureValidator == nil {
		return errors.New("posting-aware repository required")
	}
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			b.stopped = true
			return nil, nil
		}); e != nil {
			r.stopped = true
			return e
		}
	}
	r.stopped = true
	rows, e := r.rateHistory()
	if e != nil {
		return e
	}
	now := time.Now()
	for _, row := range rows {
		if row.record.At >= domain.Time(now.UnixNano()) {
			return abuse.ErrRateClock
		}
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	site.MinimumReader = max(site.MinimumReader, 70)
	changes := []store.Mutation{mutation("site", "state", site, nil)}
	newAdmission := r.admission == nil
	if newAdmission {
		policy := initialAdmission(now)
		policy.Defaults.Enabled = false
		changes = append(changes, mutation("rate_policy", "active", policy, nil))
	}
	if r.anonymous == nil {
		p := AnonymousPolicy{Schema: "anon-policy-v4", Mode: "required", Modes: []anonymousModeBoundary{}, Enabled: domain.Time(now.UnixNano()), Generation: 1, KeyID: 4, ReplyRule: domain.NewID(), CreateRule: domain.NewID()}
		changes = append(changes, mutation("anon_policy", "active", p, nil))
	}
	if e = appendControl(r.site, "posting_policies_enable", changes, []string{site.ID.String()}); e != nil {
		return e
	}
	if newAdmission {
		if e = r.loadAdmission(); e != nil {
			return e
		}
	}
	// 全板は排出済みであり、anonymous参照の書換えと投稿が競合しない。
	if e = r.loadAnonymous(); e != nil {
		return e
	}
	for _, b := range r.posting {
		if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.admission = r.admission; b.stopped = false; return nil, nil }); e != nil {
			return e
		}
	}
	r.stopped = false
	return nil
}

// pruneBoardKeys は制限器で回収済みの主体を板別追跡表から除く。admission mutex必須。
func (a *admission) pruneBoardKeys() {
	for _, keys := range a.boardKeys {
		a.limits.RetainKeys(keys)
	}
}

// ratesForBoard は既存v1の有効状態を保ち、オンライン初回有効化で他板の間隔制限を変えない。
// admission mutexの下、または起動時の単独復旧で使う。
func (a *admission) ratesForBoard(board domain.ID) AdminRateSettings {
	if a.globalRates != nil {
		return *a.globalRates
	}
	if v, ok := a.boardRates[board]; ok {
		return v
	}
	return a.policy.Defaults
}

// applyGlobalRates は全板の既存キーと消費量を維持し、共通条件を補充境界で適用する。
func (a *admission) applyGlobalRates(v AdminRateSettings, at time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.applyGlobalRatesLocked(v, at)
}
func (a *admission) applyGlobalRatesLocked(v AdminRateSettings, at time.Time) error {
	a.globalRates = &v
	for owner := range a.boardKeys {
		if err := a.applyBoardRatesLocked(owner, v, at); err != nil {
			return err
		}
	}
	return nil
}
