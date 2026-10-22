// 元の現在解除と物理正本を再照合し、最低readerと署名付き回収一覧をsite所有列へSyncする。
package bootstrap

import (
	"context"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"time"
)

// registerCaseRetirementLocked は共通lifecycle/Repository排他内で現在元snapshotから一覧を固定する。
// 同一登録の再送は署名bytesとsite版を維持する。物理削除や保存枠の解放は行わない。
func (r *Repository) registerCaseRetirementLocked(ctx context.Context, candidate disclosure.CaseRetirementCandidate, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, now time.Time) (disclosure.CaseRetirementIntent, error) {
	if e := r.available(); e != nil {
		return disclosure.CaseRetirementIntent{}, e
	}
	intent, event, e := r.evidenceCases.BuildCaseRetirementIntent(ctx, candidate, required, optional, now)
	if e != nil {
		return intent, e
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return intent, e
	}
	if row, exists := r.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]; exists {
		return r.checkCaseRetirementReplay(row, site, intent)
	}
	if e = ctx.Err(); e != nil {
		return intent, e
	}
	registration := caseRetirementRegistration{Schema: caseRetirementRegistrySchema, Site: site.ID, Fingerprint: intent.Fingerprint, Event: event}
	site.MinimumReader = max(site.MinimumReader, caseRetirementReader)
	changes := []store.Mutation{mutation("site", "state", site, nil), mutation("case_retirement", intent.Fingerprint.String(), registration, nil)}
	if e = appendControl(r.site, "case_retirement_register", changes, []string{}); e != nil {
		r.stopped = true
		return intent, e
	}
	return intent, nil
}

// checkCaseRetirementReplay は現在物理一覧/元解除へ登録済み署名を照合し、時刻を取り直さない。
func (r *Repository) checkCaseRetirementReplay(row store.ControlRow, site siteState, wanted disclosure.CaseRetirementIntent) (disclosure.CaseRetirementIntent, error) {
	v, e := decodeCaseRetirementRegistration(wanted.Fingerprint.String(), row.Value)
	if e != nil {
		return wanted, e
	}
	if row.Expires != nil || v.Site != site.ID || site.MinimumReader < caseRetirementReader {
		return wanted, store.ErrCorrupt
	}
	old, e := r.evidenceCases.VerifyCaseRetirementIntent(v.Event, wanted.Fingerprint)
	if e != nil {
		return wanted, e
	}
	if old.At > wanted.At {
		return wanted, evidence.ErrRetirementClock
	}
	wanted.At = old.At
	if !reflect.DeepEqual(old, wanted) {
		return wanted, store.ErrCorrupt
	}
	return old, nil
}
