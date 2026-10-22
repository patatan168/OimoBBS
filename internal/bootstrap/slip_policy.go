// 独自ワッチョイと全投稿Cookie必須の開始境界を耐久保存する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

type slipPolicy struct {
	Version   uint32      `json:"version"`
	Activated domain.Time `json:"activated_at_ns"`
}

func validateSlipPolicy(key string, old, next json.RawMessage) error {
	var p slipPolicy
	if key != "active" || strictjson.Decode(next, &p) != nil || p.Version != 2 || p.Activated <= 0 || len(old) != 0 && !bytes.Equal(old, next) {
		return store.ErrCorrupt
	}
	return nil
}

// loadSlipPolicy は全投稿Cookie必須の開始境界を復元する。
func (r *Repository) loadSlipPolicy() error {
	row, ok := r.site.State().Rows["slip_policy:active"]
	if !ok {
		return nil
	}
	var p slipPolicy
	var site siteState
	if strictjson.Decode(row.Value, &p) != nil || strictjson.Decode(r.site.State().Rows["site:state"].Value, &site) != nil || site.MinimumReader < 70 || r.admission == nil || r.anonymous == nil || r.anonymous.policy.Mode != "required" || r.anonymous.policy.Schema != "anon-policy-v4" || p.Activated < r.anonymous.policy.Enabled || p.Activated > domain.Time(time.Now().UnixNano()) {
		return store.ErrCorrupt
	}
	r.admission.mandatoryCookieFrom = p.Activated
	r.liveSlipEnabled.Store(true)
	return nil
}

// EnableSlip は公開受付開始前に実行し、新形式のCookieポリシーを用意し、全投稿を必須化する。
// 保存失敗時は受付を停止したままにする。再起動で同じ境界を使い、既存DATを再生成しない。
func (r *Repository) EnableSlip() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	if r.liveSlipEnabled.Load() {
		return nil
	}
	if err := r.ensureOnlinePostingPolicies(); err != nil {
		return err
	}
	if err := r.stopForAnonymousChange(); err != nil {
		return err
	}
	rows, err := r.rateHistory()
	if err != nil {
		return err
	}
	now := domain.Time(time.Now().UnixNano())
	if int64(now) < r.controlExpiryFloor.Load() {
		return ErrControlExpiryClock
	}
	for _, row := range rows {
		if row.record.At >= now {
			return errors.New("slip activation clock precedes accepted post")
		}
	}
	var changes []store.Mutation
	var site siteState
	if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	site.MinimumReader = max(site.MinimumReader, 70)
	changes = append(changes, mutation("site", "state", site, nil), mutation("slip_policy", "active", slipPolicy{2, now}, nil))
	if err = appendControl(r.site, "slip_v2_enable", changes, []string{site.ID.String()}); err != nil {
		return err
	}
	if err = r.loadAnonymous(); err != nil {
		return err
	}
	if err = r.loadSlipPolicy(); err != nil {
		return err
	}
	r.stopped = false
	r.resumeAnonymousBoards()
	if r.stopped {
		return ErrPostingUnavailable
	}
	return nil
}
