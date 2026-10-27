// 固定のサイト・ネットワーク投稿数上限を、有界列・作業予約と設定可能なWAFへ引き継ぐ。
package bootstrap

import (
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

const postingResourcesReader = 90
const postingResourcesCollection = "posting_resources"

type postingResourcePolicy struct {
	At domain.Time `json:"enabled_at_ns"`
}

func validatePostingResources(key string, old, next []byte) error {
	var policy postingResourcePolicy
	if key != "active" || len(old) != 0 || strictjson.Decode(next, &policy) != nil || policy.At <= 0 {
		return store.ErrCorrupt
	}
	return nil
}

// enablePostingResources は公開受付の開始前に新しい受付境界を同期保存する。サイトmutex必須。
// 旧バイナリの起動を防ぎ、過去の投稿は元の固定枠で復旧検査できるよう時刻を残す。
func (r *Repository) enablePostingResources() error {
	var policy postingResourcePolicy
	if row, ok := r.site.State().Rows[postingResourcesCollection+":active"]; ok {
		if err := strictjson.Decode(row.Value, &policy); err != nil {
			return err
		}
	} else {
		policy.At = domain.Time(time.Now().UnixNano())
		var site siteState
		if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
			return err
		}
		site.MinimumReader = max(site.MinimumReader, postingResourcesReader)
		if err := appendControl(r.site, "posting_resources_enable", []store.Mutation{mutation("site", "state", site, nil), mutation(postingResourcesCollection, "active", policy, nil)}, []string{}); err != nil {
			r.stopped = true
			return err
		}
	}
	if r.admission != nil {
		r.admission.mu.Lock()
		r.admission.resourceFrom = policy.At
		r.admission.mu.Unlock()
	}
	return nil
}

// resourceCharges は保存済み境界以降だけ固定の全体・ネットワーク枠を外す。
// 保存するRateKeyは従来通り維持し、利用者の投稿間隔・Cookie・条件規制には触れない。
func (a *admission) resourceCharges(charges []abuse.RateCharge, at domain.Time) []abuse.RateCharge {
	if a.resourceFrom == 0 || at < a.resourceFrom {
		return charges
	}
	network := a.policy.Rules[2].ID.String() + ":"
	site := a.policy.Rules[3].ID.String() + ":"
	result := charges[:0]
	for _, charge := range charges {
		if !strings.HasPrefix(charge.Key, network) && !strings.HasPrefix(charge.Key, site) {
			result = append(result, charge)
		}
	}
	return result
}
