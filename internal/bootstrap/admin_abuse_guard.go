// 全板共通の荒らし対策を認可・CAS・再送照合付きで保存し、投稿履歴を維持して適用する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type guardState struct {
	Settings AbuseGuardSettings `json:"settings"`
	Changed  domain.Time        `json:"changed_at_ns"`
}

// AdminAbuseGuard は全板共通設定と、本文を含まない直近検出記録を返す。
type AdminAbuseGuard struct {
	Settings   AbuseGuardSettings `json:"settings"`
	Revision   domain.U64         `json:"revision"`
	Events     []GuardEvent       `json:"events"`
	Configured bool               `json:"configured"`
}

// ETag はサイト共通対策の競合検出版を返す。
func (v AdminAbuseGuard) ETag() string { return fmt.Sprintf(`"abuse-guard:%d"`, v.Revision) }

type guardReceipt struct {
	ID       domain.ID          `json:"id"`
	Admin    domain.ID          `json:"admin_id"`
	Key      domain.Hash        `json:"key_hmac"`
	Request  domain.Hash        `json:"request_hmac"`
	Settings AbuseGuardSettings `json:"settings"`
	Revision domain.U64         `json:"revision"`
	Created  domain.Time        `json:"created_at_ns"`
	Expires  domain.Time        `json:"expires_at_ns"`
}

// validateGuardValue は新規コレクションの未知キー・null・範囲外・時刻逆行を拒否する。
func validateGuardValue(collection, key string, old, next json.RawMessage) error {
	switch collection {
	case "global_posting_policy":
		return validateBoardPostingPolicy(key, old, next)
	case "abuse_guard":
		var v guardState
		if key != "active" || strictjson.Decode(next, &v) != nil || v.Changed <= 0 || v.Settings.validate() != nil {
			return store.ErrCorrupt
		}
		if len(old) > 0 {
			var p guardState
			if strictjson.Decode(old, &p) != nil || v.Changed <= p.Changed {
				return store.ErrCorrupt
			}
		}
	case "abuse_guard_receipt":
		var v guardReceipt
		if strictjson.Decode(next, &v) != nil || key != v.Key.String() || v.Key == (domain.Hash{}) || v.Request == (domain.Hash{}) || v.ID == (domain.ID{}) || v.Admin == (domain.ID{}) || v.Revision == 0 || v.Created <= 0 || v.Created > domain.Time(1<<63-1)-86400e9 || v.Expires != v.Created+86400e9 || v.Settings.validate() != nil {
			return store.ErrCorrupt
		}
		if len(old) > 0 {
			var p guardReceipt
			if strictjson.Decode(old, &p) != nil || p.Expires > v.Created {
				return store.ErrCorrupt
			}
		}
	default:
		return store.ErrCorrupt
	}
	return nil
}

// globalPostingPolicies は変更時刻順の共通投稿枠条件を復旧する。板別の旧履歴は変更しない。
func globalPostingPolicies(state store.ControlState) ([]boardPostingPolicy, error) {
	var out []boardPostingPolicy
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "global_posting_policy:") {
			continue
		}
		var p boardPostingPolicy
		if row.Expires != nil || strictjson.Decode(row.Value, &p) != nil || validateBoardPostingPolicy(strings.TrimPrefix(name, "global_posting_policy:"), nil, row.Value) != nil {
			return nil, store.ErrCorrupt
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At < out[j].At })
	if len(out) > 10000 {
		return nil, store.ErrCorrupt
	}
	for i := 1; i < len(out); i++ {
		if out[i].At <= out[i-1].At {
			return nil, store.ErrCorrupt
		}
	}
	return out, nil
}

// inspectGuardState は正本設定・履歴・再送版と最低readerの一致を起動/backupで確認する。
func inspectGuardState(state store.ControlState, site siteState) error {
	policies, err := globalPostingPolicies(state)
	if err != nil {
		return err
	}
	active, exists := state.Rows["abuse_guard:active"]
	for name, row := range state.Rows {
		if !strings.HasPrefix(name, "abuse_guard:") && !strings.HasPrefix(name, "abuse_guard_receipt:") && !strings.HasPrefix(name, "global_posting_policy:") {
			continue
		}
		if !exists || site.MinimumReader < 78 || row.Expires != nil {
			return store.ErrCorrupt
		}
		if strings.HasPrefix(name, "abuse_guard_receipt:") {
			var v guardReceipt
			if strictjson.Decode(row.Value, &v) != nil || v.Revision > active.Revision {
				return store.ErrCorrupt
			}
		}
	}
	if exists {
		var v guardState
		if strictjson.Decode(active.Value, &v) != nil || len(policies) == 0 || policies[len(policies)-1].Rates != v.Settings.Rates || policies[len(policies)-1].At > v.Changed || v.Changed > domain.Time(time.Now().UnixNano()) {
			return store.ErrCorrupt
		}
	}
	return nil
}

// guardView はRepository mutexの下で設定と検出一覧の独立コピーを返す。
func (r *Repository) guardView() AdminAbuseGuard {
	g := r.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	return AdminAbuseGuard{g.settings, r.site.State().Rows["abuse_guard:active"].Revision, append([]GuardEvent{}, g.events...), g.configured}
}

// adminAbuseGuard はsite_adminだけが共通設定を変更する。edit=nilは取得。
func (r *Repository) adminAbuseGuard(s adminauth.Session, edit *AbuseGuardSettings, etag, key string) (AdminAbuseGuard, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.currentAdministrator(s); err != nil {
		return AdminAbuseGuard{}, err
	}
	if err := r.available(); err != nil {
		return AdminAbuseGuard{}, err
	}
	current := r.guardView()
	if edit == nil {
		return current, nil
	}
	if edit.validate() != nil {
		return AdminAbuseGuard{}, &adminFailure{status: 422, code: "INVALID_SETTINGS"}
	}
	if !adminRequestKey.MatchString(key) {
		return AdminAbuseGuard{}, &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if etag == "" {
		return AdminAbuseGuard{}, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	master, err := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if err != nil {
		return AdminAbuseGuard{}, err
	}
	defer clear(master)
	secret, err := identity.DeriveKey(master, "dedup", 8)
	if err != nil {
		return AdminAbuseGuard{}, err
	}
	defer clear(secret[:])
	requestKey := identity.MAC(secret[:], "oimo/abuse-guard-key/v1", s.Admin[:], []byte(key))
	raw, _ := json.Marshal(edit)
	request := identity.MAC(secret[:], "oimo/abuse-guard/v1", s.Admin[:], raw, []byte(etag))
	now := domain.Time(time.Now().UnixNano())
	state := r.site.State()
	if row, ok := state.Rows["abuse_guard_receipt:"+requestKey.String()]; ok {
		var p guardReceipt
		if err := strictjson.Decode(row.Value, &p); err != nil {
			return AdminAbuseGuard{}, err
		}
		if p.Created > now {
			return AdminAbuseGuard{}, ErrPostingUnavailable
		}
		if p.Expires > now {
			if p.Request != request {
				return AdminAbuseGuard{}, &adminFailure{status: 409, code: "REQUEST_CONFLICT"}
			}
			return AdminAbuseGuard{p.Settings, p.Revision, current.Events, true}, nil
		}
	}
	if etag != current.ETag() {
		return AdminAbuseGuard{}, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	count := 0
	for name := range state.Rows {
		if strings.HasPrefix(name, "abuse_guard_receipt:") {
			count++
		}
	}
	if count >= 200000 {
		return AdminAbuseGuard{}, ErrPostingUnavailable
	}
	policies, err := globalPostingPolicies(state)
	if err != nil {
		return AdminAbuseGuard{}, err
	}
	if len(policies) >= 10000 {
		return AdminAbuseGuard{}, ErrPostingUnavailable
	}
	if err = r.ensureOnlinePostingPolicies(); err != nil {
		return AdminAbuseGuard{}, err
	}
	// 全板の進行中バッチを確定させ、保存境界をまたぐ旧設定の受理を防ぐ。
	for _, b := range r.posting {
		if _, err = b.worker.Submit(context.Background(), func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			b.stopped = true
			return nil, nil
		}); err != nil {
			r.stopped = true
			return AdminAbuseGuard{}, err
		}
	}
	resume := false
	defer func() {
		if resume {
			for _, b := range r.posting {
				_, _ = b.worker.Submit(context.Background(), func() (any, error) { b.stopped = false; return nil, nil })
			}
		}
	}()
	now = domain.Time(time.Now().UnixNano())
	state = r.site.State()
	g := r.guard
	g.mu.Lock()
	defer g.mu.Unlock()
	if now <= g.floor || now <= r.admission.lastReserved {
		resume = true
		return AdminAbuseGuard{}, ErrControlExpiryClock
	}
	var site siteState
	if err = strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		r.stopped = true
		return AdminAbuseGuard{}, err
	}
	site.MinimumReader = max(site.MinimumReader, 78)
	receipt := guardReceipt{domain.NewID(), s.Admin, requestKey, request, *edit, state.Seq + 1, now, now + 86400e9}
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("abuse_guard", "active", guardState{*edit, now}, nil), mutation("abuse_guard_receipt", requestKey.String(), receipt, nil)}
	if len(policies) == 0 || policies[len(policies)-1].Rates != edit.Rates {
		policy := boardPostingPolicy{domain.NewID(), now, edit.Rates}
		changes = append(changes, mutation("global_posting_policy", policy.ID.String(), policy, nil))
	}
	kid := uint32(8)
	frame, err := controlFrame(state, receipt.ID, now, "abuse_guard_update", changes, []string{site.ID.String()}, domain.Actor{Kind: "admin", ID: &s.Admin, Reason: "abuse_guard_update", Request: &request, Idempotency: &requestKey, KeyID: &kid})
	if err != nil {
		resume = true
		return AdminAbuseGuard{}, err
	}
	if saved := r.site.Append(frame); saved.Status != store.Durable {
		r.stopped = true
		return AdminAbuseGuard{}, &adminFailure{status: 503, code: "SAVE_UNCERTAIN", operation: receipt.ID}
	}
	if err = r.admission.applyGlobalRates(edit.Rates, time.Unix(0, int64(now))); err != nil {
		r.stopped = true
		return AdminAbuseGuard{}, err
	}
	g.settings = *edit
	g.configured = true
	g.floor = now
	resume = true
	return AdminAbuseGuard{*edit, receipt.Revision, append([]GuardEvent{}, g.events...), true}, nil
}
