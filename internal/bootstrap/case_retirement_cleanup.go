// 既存の毎分期限処理で閉鎖180日案件を先行登録・物理回収する。
package bootstrap

import (
	"context"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
	"time"
)

// reclaimCaseRetirementsLocked は共通lifecycle/Repository排他下で期限到達した管理履歴を回収する。
// 全現在元を検査し、一覧と最低readerの先行Sync後だけ削除する。不確定削除では製品所有者を停止する。
func (r *Repository) reclaimCaseRetirementsLocked(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	now := time.Now()
	plans, e := r.evidenceCases.PlanCaseRetirement(now)
	if e != nil || len(plans) == 0 {
		return e
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	// 元の現在集合は起動と同じ読取り署名検査で取得する。検査失敗では登録/削除を始めない。
	seed, key, e := readRetirementKey(r.cfg.DataDir)
	if e != nil {
		return e
	}
	defer clear(seed)
	defer clear(key)
	required, optional, e := retirementStartupSources(r.cfg, site, r.site.State(), key)
	if e != nil {
		return e
	}
	for _, plan := range plans {
		if e = r.saveAndReclaimCaseLocked(ctx, plan, required.Receipts, optional, site.MinimumReader, now); e != nil {
			return e
		}
	}
	return nil
}

// saveAndReclaimCaseLocked は保存枠を確保し、既存site登録がSyncした後にだけ物理回収する。
func (r *Repository) saveAndReclaimCaseLocked(ctx context.Context, candidate disclosure.CaseRetirementCandidate, required []app.RequiredHoldReceipt, optional []evidence.OptionalHoldReceipt, reader uint32, now time.Time) error {
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return e
	}
	defer release()
	intent, e := r.registerCaseRetirementLocked(ctx, candidate, required, optional, now)
	if e != nil {
		return e
	}
	row, e := decodeCaseRetirementRegistration(intent.Fingerprint.String(), r.site.State().Rows["case_retirement:"+intent.Fingerprint.String()].Value)
	if e != nil {
		return e
	}
	if e = r.evidenceCases.ReclaimCaseRetirement(ctx, candidate.Case, row.Event, max(reader, caseRetirementReader), required, optional, now); e != nil {
		r.stopped = true
		return e
	}
	return nil
}
