// 規制の明示有効化と、確定投稿からの起動復旧を所有排他の下で行う。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"sort"
	"time"
)

func (r *Repository) loadAdmission() error {
	row, exists := r.site.State().Rows["rate_policy:active"]
	if !exists {
		return nil
	}
	p, e := validateAdmission(row.Value)
	if e != nil {
		return e
	}
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return e
	}
	defer clear(master)
	secret, e := identity.DeriveKey(master, "rate", 7)
	if e != nil {
		return e
	}
	r.admission = &admission{policy: p, secret: secret, limits: abuse.NewLimiter(200000), boardRates: map[domain.ID]AdminRateSettings{}, boardKeys: map[domain.ID]map[string]bool{}}

	if row, exists := r.site.State().Rows[postingResourcesCollection+":active"]; exists {
		var policy postingResourcePolicy
		if err := strictjson.Decode(row.Value, &policy); err != nil {
			return err
		}
		r.admission.resourceFrom = policy.At
	}
	return nil
}

type boardRateRecord struct {
	owner  domain.ID
	key    uint64
	record app.RateRecord
}

func (r *Repository) rateHistory() ([]boardRateRecord, error) {
	rows := []boardRateRecord{}
	for owner, b := range r.posting {
		value, e := b.worker.Submit(context.Background(), func() (any, error) {
			data := []boardRateRecord{}
			for key, p := range b.threads {
				var last domain.Time
				history, e := p.RateHistory()
				if e != nil {
					return nil, e
				}
				for _, v := range history {
					if _, e := retiredRateHistoryRow(boardRateRecord{owner, key, v}, domain.Time(time.Now().UnixNano())); e != nil {
						return nil, e
					}
					if v.At < last {
						return nil, abuse.ErrRateClock
					}
					last = v.At
					data = append(data, boardRateRecord{owner, key, v})
				}
			}
			return data, nil
		})
		if e != nil {
			return nil, e
		}
		rows = append(rows, value.([]boardRateRecord)...)
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.record.At != b.record.At {
			return a.record.At < b.record.At
		}
		return a.record.ID.String() < b.record.ID.String()
	})
	return rows, nil
}
func (r *Repository) restoreAdmission() error {
	if r.admission == nil {
		return nil
	}
	now := time.Now()
	a := r.admission
	if domain.Time(now.UnixNano()) < a.policy.Enabled {
		return abuse.ErrRateClock
	}
	rows, e := r.rateHistory()
	if e != nil {
		return e
	}

	type policyEvent struct {
		owner  domain.ID
		policy boardPostingPolicy
		global bool
	}
	events := []policyEvent{}
	for owner, b := range r.posting {
		policies, e := postingPolicies(b.control.State())
		if e != nil {
			return e
		}
		for _, p := range policies {
			if p.At < a.policy.Enabled || p.At > domain.Time(now.UnixNano()) {
				return abuse.ErrRateClock
			}
			events = append(events, policyEvent{owner, p, false})
		}
	}
	var globalPolicies []boardPostingPolicy
	var err error
	if r.site != nil {
		globalPolicies, err = globalPostingPolicies(r.site.State())
	}
	if err != nil {
		return err
	}
	for _, p := range globalPolicies {
		if p.At < a.policy.Enabled || p.At > domain.Time(now.UnixNano()) {
			return abuse.ErrRateClock
		}
		events = append(events, policyEvent{policy: p, global: true})
	}
	sort.Slice(events, func(i, j int) bool { return events[i].policy.At < events[j].policy.At })
	nextEvent := 0
	applyUntil := func(at domain.Time) error {
		for nextEvent < len(events) && events[nextEvent].policy.At <= at {
			v := events[nextEvent]
			var e error
			if v.global {
				e = a.applyGlobalRates(v.policy.Rates, time.Unix(0, int64(v.policy.At)))
			} else {
				e = a.applyBoardRates(v.owner, v.policy.Rates, time.Unix(0, int64(v.policy.At)))
			}
			if e != nil {
				return e
			}
			nextEvent++
		}
		return nil
	}
	var pruned time.Time
	for _, row := range rows {
		v := row.record
		if retired, e := retiredRateHistoryRow(row, domain.Time(now.UnixNano())); e != nil {
			return e
		} else if retired {
			continue
		}
		if e = a.validate(row.owner, v); e != nil {
			return e
		}
		if v.At > a.policy.Enabled && v.At > domain.Time(now.UnixNano()) {
			return abuse.ErrRateClock
		}
		if v.At < a.policy.Enabled || v.At < domain.Time(now.Add(-61*time.Minute).UnixNano()) {
			continue
		}
		if e := applyUntil(v.At); e != nil {
			return e
		}
		ip, e := parseRateIP(v.IP)
		if e != nil {
			return e
		}
		charges, _ := a.charges(row.owner, ip, v.Create)
		charges = a.resourceCharges(charges, v.At)
		if v.TokenStatus == "valid" && v.Token != nil {
			rule := a.anonymous.ReplyRule
			settings := a.ratesForBoard(row.owner)
			spec := settings.spec(v.Create)
			if v.Create {
				rule = a.anonymous.CreateRule
			}
			for _, key := range v.Keys {
				if key.Rule == rule {
					charges = append(charges, abuse.RateCharge{Key: rule.String() + ":" + key.Subject.String(), Spec: spec, Cost: 1})
				}
			}
		}
		for _, id := range v.Overrides {
			c, _ := a.overrideCharge(row.owner, ip, a.overrides[row.owner][id])
			charges = append(charges, c)
		}
		at := time.Unix(0, int64(v.At))
		if pruned.IsZero() || at.Sub(pruned) >= time.Minute {
			a.limits.Prune(at)
			a.pruneBoardKeys()
			pruned = at
		}
		a.trackBoardCharges(row.owner, v.Create, charges)
		a.lastReserved = v.At
		ticket, e := a.limits.Reserve(at, charges)
		if e != nil {
			return errors.New("cannot reconstruct accepted rate history")
		}
		if e = a.limits.Commit(ticket); e != nil {
			return e
		}
	}
	return applyUntil(domain.Time(now.UnixNano()))
}

// EnableAdmission は停止中の所有者専用。旧投稿を変更せず、policyと最低reader版を一括保存する。
// 初回有効化を試みた後は、失敗時もこのRepositoryを閉じて再起動する。
func (r *Repository) EnableAdmission() (AdmissionPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return AdmissionPolicy{}, e
	}
	if r.captureValidator == nil {
		return AdmissionPolicy{}, errors.New("posting-aware repository required")
	}
	if r.admission != nil {
		return r.admission.policy, nil
	}
	// 呼出し前に取得済みの板参照からも、有効化境界を越えて旧形式を書けないよう排出する。
	r.stopped = true
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) { b.stopped = true; return nil, nil }); e != nil {
			return AdmissionPolicy{}, e
		}
	}
	rows, e := r.rateHistory()
	if e != nil {
		return AdmissionPolicy{}, e
	}
	now := time.Now()
	at := domain.Time(now.UnixNano())
	for _, v := range rows {
		if v.record.At >= at || len(v.record.Keys) != 0 {
			return AdmissionPolicy{}, errors.New("existing rate history prevents activation")
		}
	}
	policy := initialAdmission(now)
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return AdmissionPolicy{}, e
	}
	site.MinimumReader = max(site.MinimumReader, 19)
	e = appendControl(r.site, "admission_enable", []store.Mutation{mutation("site", "state", site, nil), mutation("rate_policy", "active", policy, nil)}, []string{site.ID.String()})
	r.stopped = true
	return policy, e
}
