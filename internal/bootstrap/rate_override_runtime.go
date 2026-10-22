// 追加規制枠を通常枠と一括予約し、署名付き受理履歴から同じ枠を復元する。
package bootstrap

import (
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"slices"
	"sort"
	"strings"
)

func matchedOverrides(matched map[domain.ID]denialRule) []domain.ID {
	excluded := excludedRules(matched)
	ids := []domain.ID{}
	for id, rule := range matched {
		if rule.Effect.Type == "rate_override" && !excluded[id] {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b domain.ID) int { return strings.Compare(a.String(), b.String()) })
	return ids
}

func allowTargetsOverride(rules map[domain.ID]compiledDenial, ids []domain.ID) bool {
	for _, id := range ids {
		if rules[id].rule.Effect.Type == "rate_override" {
			return true
		}
	}
	return false
}

// checkRuleClock は新規規制を過去の受理へ遡及させず、停止時刻も最後の予約より後に固定する。
func (b *postingBoard) checkRuleClock(now domain.Time) error {
	if b.admission == nil {
		return ErrPostingUnavailable
	}
	b.admission.mu.Lock()
	defer b.admission.mu.Unlock()
	if now <= max(b.admission.policy.Enabled, b.admission.lastReserved) {
		return abuse.ErrRateClock
	}
	return nil
}

// installOverrides は所有者がSyncした不変の仕様だけを共通予約器へ複製する。
func (a *admission) installOverrides(board domain.ID, rules map[domain.ID]compiledDenial) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.overrides == nil {
		a.overrides = map[domain.ID]map[domain.ID]denialRule{}
	}
	values := map[domain.ID]denialRule{}
	for id, entry := range rules {
		if entry.rule.Effect.Type == "rate_override" {
			values[id] = entry.rule
		}
	}
	a.overrides[board] = values
}

func (a *admission) overrideCharge(board domain.ID, ip netip.Addr, rule denialRule) (abuse.RateCharge, domain.RateKey) {
	h := identity.MAC(a.secret[:], "oimo/rate/v1", rule.ID[:], board[:], []byte("ip"), []byte(ip.Unmap().String()))
	return abuse.RateCharge{Key: rule.ID.String() + ":" + h.String(), Spec: rule.Effect.Rate.spec(), Cost: 1}, domain.RateKey{Rule: rule.ID, KeyID: 7, Subject: h, Cost: 1}
}

// validateOverridesLocked は追加IDをIP主体へ再結合し、従来枠の検査へ渡すコピーからのみ除く。
func (a *admission) validateOverridesLocked(board domain.ID, record *app.RateRecord) error {
	if len(record.Overrides) > 12 || len(record.Overrides) > 0 && record.Schema != postcapture.Schema {
		return store.ErrCorrupt
	}
	if record.Schema != postcapture.Schema {
		for _, rule := range a.overrides[board] {
			if record.At >= rule.Starts {
				return store.ErrCorrupt
			}
		}
	}
	for i := 1; i < len(record.Keys); i++ {
		if record.Keys[i-1].Rule.String() >= record.Keys[i].Rule.String() {
			return store.ErrCorrupt
		}
	}
	ip, err := parseRateIP(record.IP)
	if err != nil {
		return err
	}
	keys := append([]domain.RateKey{}, record.Keys...)
	prior := ""
	for _, id := range record.Overrides {
		if id.String() <= prior {
			return store.ErrCorrupt
		}
		prior = id.String()
		rule, ok := a.overrides[board][id]
		if !ok || record.At < rule.Starts || record.At >= rule.Expires || !rule.Enabled && (rule.Effect.Stopped == nil || record.At >= *rule.Effect.Stopped) {
			return store.ErrCorrupt
		}
		_, want := a.overrideCharge(board, ip, rule)
		found := -1
		for i, key := range keys {
			if key == want {
				if found >= 0 {
					return store.ErrCorrupt
				}
				found = i
			}
		}
		if found < 0 {
			return store.ErrCorrupt
		}
		keys = slices.Delete(keys, found, found+1)
	}
	record.Keys = keys
	return nil
}

// validateOverrideCapture は現在の解除状態に依存せず、受理時刻の条件成立集合を照合する。
func (b *postingBoard) validateOverrideCapture(raw []byte) error {
	capture, _, _, err := postcapture.OverrideMetadata(raw)
	if err != nil || capture == nil {
		return err
	}
	return b.validateOverrideCaptureValue(capture)
}

// validateOverrideCaptureValue は完全型を検査済みの記録を、保存時の規制へ照合する。
func (b *postingBoard) validateOverrideCaptureValue(capture *postcapture.Capture) error {
	if capture == nil {
		return nil
	}
	token, ids := capture.Token, capture.Overrides
	ip, err := parseRateIP(capture.Observation.Resolved.IP)
	if err != nil {
		return err
	}
	subject := domain.Hash{}
	if token != nil {
		subject = token.Subject
	}
	matched, err := b.matchedRules(ip, capture.Input, subject, capture.Target == 0, capture.Committed, capture.Observation.SelectedHeaders, true)
	if err != nil {
		return err
	}
	if !slices.Equal(ids, matchedOverrides(matched)) {
		return store.ErrCorrupt
	}
	return nil
}

// validateOverrideHistory は同時有効数と、停止済み除外規制の復旧時刻を検証する。
func validateOverrideHistory(rules map[domain.ID]compiledDenial) error {
	type event struct {
		at    domain.Time
		delta int
	}
	events := []event{}
	for _, entry := range rules {
		rule := entry.rule
		if rule.Effect.Type == "allow_rule_ids" && !rule.Enabled && allowTargetsOverride(rules, rule.Effect.IDs) && rule.Effect.Stopped == nil {
			return store.ErrCorrupt
		}
		if rule.Effect.Type != "rate_override" {
			continue
		}
		end := rule.Expires
		if rule.Effect.Stopped != nil {
			end = min(end, *rule.Effect.Stopped)
		}
		if end > rule.Starts {
			events = append(events, event{rule.Starts, 1}, event{end, -1})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].at != events[j].at {
			return events[i].at < events[j].at
		}
		return events[i].delta < events[j].delta
	})
	count := 0
	for _, event := range events {
		count += event.delta
		if count > 12 {
			return store.ErrCorrupt
		}
	}
	return nil
}
