// 回収登録と現在HTTP元解除を照合し、完全回収済み案件の元索引掃除候補を非変更で選ぶ。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// optionalHoldRetirementPlan は元所有列で再照合するための一時入力。保存/HTTP出力を行わない。
type optionalHoldRetirementPlan struct {
	Fingerprint  domain.Hash
	Registration evidence.Event
	Released     evidence.OptionalHoldReceipt
}

// planCompletedOptionalHolds は検査済み元snapshotと現在案件を受ける。呼出元はlifecycle/所有者排他を保持する。
// 最新登録の署名/時計と全集合を先に検査し、部分削除・現存案件を回収済みへ読み替えない。
func planCompletedOptionalHolds(ctx context.Context, root string, key ed25519.PrivateKey, state store.ControlState, cases []disclosure.Case, sources []evidence.OptionalHoldReceipt, now time.Time) ([]optionalHoldRetirementPlan, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, store.ErrCorrupt
	}
	intents, err := verifiedRetirementIntents(state, key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano()))
	if err != nil {
		return nil, err
	}
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return nil, err
	}
	registrations, err := caseRetirementRegistrations(state, site)
	if err != nil {
		return nil, err
	}
	live := map[domain.ID]bool{}
	for _, c := range cases {
		live[c.ID] = true
	}
	fingerprint := func(id domain.ID) domain.Hash { hash, _ := disclosure.CaseRetirementFingerprint(key, id); return hash }
	if _, err := optionalSourcesWithRetirements(sources, live, intents, fingerprint, domain.Time(now.UnixNano())); err != nil {
		return nil, err
	}
	return selectCompletedOptionalHolds(ctx, root, key, site.MinimumReader, sources, live, registrations, fingerprint, now)
}

func selectCompletedOptionalHolds(ctx context.Context, root string, key ed25519.PrivateKey, reader uint32, sources []evidence.OptionalHoldReceipt, live map[domain.ID]bool, registrations map[domain.Hash]caseRetirementRegistration, fingerprint func(domain.ID) domain.Hash, now time.Time) ([]optionalHoldRetirementPlan, error) {
	plans := []optionalHoldRetirementPlan{}
	for _, source := range sources {
		id := source.Binding.Case
		hash := fingerprint(id)
		registration, found := registrations[hash]
		if !found || live[id] {
			continue
		}
		err := disclosure.InspectCompletedCaseRetirement(ctx, root, key, id, registration.Event, reader, now)
		if errors.Is(err, store.ErrIncomplete) {
			continue
		}
		if err != nil {
			return nil, err
		}
		plans = append(plans, optionalHoldRetirementPlan{hash, registration.Event, cloneOptionalRetirementSource(source)})
	}
	return plans, nil
}

// cloneOptionalRetirementSource は候補の元集合を独立所有にし、呼出元のslice変更を取り込まない。
func cloneOptionalRetirementSource(source evidence.OptionalHoldReceipt) evidence.OptionalHoldReceipt {
	source.Binding.Operations = slices.Clone(source.Binding.Operations)
	source.Items = slices.Clone(source.Items)
	return source
}
