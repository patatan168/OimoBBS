// 現在登録・案件directory不在・元解除を再照合し、元索引回収候補とreaderを同じサイトframeへSyncする。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"path/filepath"
	"reflect"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// registerOptionalHoldRetirementLocked はlifecycle/Repository排他を要求する。元fileの削除は行わない。
// 現在元解除と候補を再照合し、保存不明ならRepositoryを停止する。同一候補の再送は版を増やさない。
func (r *Repository) registerOptionalHoldRetirementLocked(ctx context.Context, plan optionalHoldRetirementPlan, candidate evidence.OptionalHoldRetirementCandidate, now time.Time) error {
	if err := r.available(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var site siteState
	state := r.site.State()
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return err
	}
	v := optionalHoldRetirementRegistration{optionalHoldRetirementSchema, site.ID, plan.Fingerprint, candidate.Previous, candidate.Next}
	if err := r.checkOptionalHoldRetirementRegistrationLocked(ctx, site, v, plan, now); err != nil {
		return err
	}
	if old, found := state.Rows[optionalHoldRetirementCollection+":"+plan.Fingerprint.String()]; found {
		return checkOptionalHoldRetirementRegistrationReplay(old, site, v)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	site.MinimumReader = max(site.MinimumReader, evidence.OptionalHoldRetirementReader)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation(optionalHoldRetirementCollection, plan.Fingerprint.String(), v, nil)}
	if err := appendControl(r.site, "optional_hold_retirement_register", changes, []string{}); err != nil {
		r.stopped = true
		return err
	}
	return nil
}

func (r *Repository) checkOptionalHoldRetirementRegistrationLocked(ctx context.Context, site siteState, v optionalHoldRetirementRegistration, plan optionalHoldRetirementPlan, now time.Time) error {
	seed, key, err := readRetirementKey(r.cfg.DataDir)
	if err != nil {
		return err
	}
	defer clear(seed)
	defer clear(key)
	if _, err := verifiedRetirementIntents(r.site.State(), key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano())); err != nil {
		return err
	}
	rows, err := caseRetirementRegistrations(r.site.State(), site)
	if err != nil {
		return err
	}
	original, found := rows[plan.Fingerprint]
	if !found || !reflect.DeepEqual(original.Event, plan.Registration) {
		return store.ErrCorrupt
	}
	desc, err := verifyOptionalHoldRetirementRegistration(v, original, key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano()))
	if err != nil {
		return err
	}
	if !r.matchesOptionalRetirementPlan(desc, plan) {
		return store.ErrCorrupt
	}
	if err := checkOptionalRetirementRegistrationProgress(r.site.State(), site, key.Public().(ed25519.PublicKey), desc); err != nil {
		return err
	}
	if err := disclosure.InspectCompletedCaseRetirement(ctx, filepath.Join(r.cfg.DataDir, "cases"), key, desc.Case, original.Event, site.MinimumReader, now); err != nil {
		return err
	}
	return r.optionalStore.CheckOptionalHoldRelease(plan.Released)
}

// checkOptionalRetirementRegistrationProgress は別案件の同seq候補や過去索引への登録を保存前に拒否する。
func checkOptionalRetirementRegistrationProgress(state store.ControlState, site siteState, key ed25519.PublicKey, wanted evidence.OptionalHoldRetirementDescription) error {
	rows, err := optionalHoldRetirementRegistrations(state, site)
	if err != nil {
		return err
	}
	for hash, row := range rows {
		if hash == wanted.Fingerprint {
			continue
		}
		old, err := evidence.VerifyOptionalHoldRetirementCandidate(site.ID, key, row.candidate())
		if err != nil {
			return err
		}
		if wanted.Sequence <= old.Sequence {
			return store.ErrCorrupt
		}
	}
	return nil
}

func (r *Repository) matchesOptionalRetirementPlan(desc evidence.OptionalHoldRetirementDescription, plan optionalHoldRetirementPlan) bool {
	return desc.Case == plan.Released.Binding.Case && desc.Release == plan.Released.SHA && r.evidenceCases.CaseRetirementFingerprint(desc.Case) == plan.Fingerprint
}

func checkOptionalHoldRetirementRegistrationReplay(row store.ControlRow, site siteState, wanted optionalHoldRetirementRegistration) error {
	old, err := decodeOptionalHoldRetirementRegistration(wanted.Fingerprint.String(), row.Value)
	if err != nil {
		return err
	}
	if row.Expires != nil || site.MinimumReader < evidence.OptionalHoldRetirementReader || !reflect.DeepEqual(old, wanted) {
		return store.ErrCorrupt
	}
	return nil
}
