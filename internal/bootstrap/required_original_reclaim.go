// 必須原本の有界回収を案件/元署名集合・公開回収完了task・共通容量へ接続する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"reflect"
	"slices"
	"time"
)

// ReclaimRequiredOriginals は指定板/キー/一日列の最大64受理操作を保護照合後に回収する。
// 原本本文を返さない。最低reader45・公開本文回収・独立carryと完了taskを必須とする。
// 案件/元共通排他と案件排他を板所有列の待ちから回収完了まで保持する。
// candidatesは内部走査で得た固定対応。内容は実原本/回収署名へ再照合する。
func (r *Repository) ReclaimRequiredOriginals(ctx context.Context, board domain.ID, key, day uint64, candidates []evidence.RequiredPostingIdentity) (int, error) {
	if len(candidates) == 0 || len(candidates) > 64 {
		return 0, store.ErrCorrupt
	}
	for _, i := range candidates {
		if i.Outcome != "accepted" {
			return 0, store.ErrCorrupt
		}
	}
	candidates = slices.Clone(candidates)
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	b, site, e := r.requiredReclaimReady(ctx, board, key, day)
	if e != nil {
		return 0, e
	}
	now := time.Now()
	guard, e := r.requiredReclaimProtection(ctx, site, now)
	if e != nil {
		return 0, e
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		return r.reclaimRequiredOriginalsOwned(ctx, b, key, day, candidates, guard, domain.Time(now.UnixNano()))
	})
	if e != nil {
		return 0, e
	}
	return value.(int), nil
}

func (r *Repository) requiredReclaimReady(ctx context.Context, id domain.ID, key, day uint64) (*postingBoard, siteState, error) {
	var site siteState
	if e := ctx.Err(); e != nil {
		return nil, site, e
	}
	if e := r.available(); e != nil {
		return nil, site, e
	}
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return nil, site, e
	}
	b := r.posting[id]
	if site.MinimumReader < 45 || b == nil || key == 0 || day == 0 {
		return nil, site, store.ErrIncomplete
	}
	return b, site, nil
}

// requiredReclaimProtection は全元の所有列で署名/時計を読み、完成copyも物理検査する。
func (r *Repository) requiredReclaimProtection(ctx context.Context, site siteState, now time.Time) (*disclosure.RequiredGCProtection, error) {
	seed, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return nil, e
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	defer clear(key)
	rows, e := disclosure.InspectRequiredCaseMetadataVersion(filepath.Join(r.cfg.DataDir, "cases"), key, site.MinimumReader)
	if e != nil {
		return nil, e
	}
	if e = r.checkRequiredReclaimCases(rows); e != nil {
		return nil, e
	}
	floor, e := r.evidenceCases.RequiredGCClockFloor()
	if e != nil {
		return nil, e
	}
	sources, sourceFloor, e := r.requiredReclaimSources(ctx, site, rows, domain.Time(now.UnixNano()))
	if e != nil {
		return nil, e
	}
	sources, e = requiredSourcesWithRetirements(r.site.State(), key, rows, sources, domain.Time(now.UnixNano()))
	if e != nil {
		return nil, e
	}
	guard, e := disclosure.PrepareRequiredGCProtection(rows, sources.Receipts, sources.Renewals, domain.Time(now.UnixNano()), max(floor, sourceFloor))
	if e != nil {
		return nil, e
	}
	e = disclosure.InspectRequiredCompletedCopies(filepath.Join(r.cfg.DataDir, "cases"), key, rows, now)
	return guard, e
}

// checkRequiredReclaimCases は読取り署名集合と現在案件所有者の版を全件照合する。
func (r *Repository) checkRequiredReclaimCases(rows []disclosure.RequiredCaseInspection) error {
	cases, e := r.evidenceCases.Cases()
	if e != nil {
		return e
	}
	if len(cases) != len(rows) {
		return store.ErrCorrupt
	}
	for _, row := range rows {
		current, e := r.evidenceCases.Get(row.Current.ID)
		if e != nil || !reflect.DeepEqual(current, row.Current) {
			return errors.Join(store.ErrCorrupt, e)
		}
	}
	return nil
}

func (r *Repository) requiredReclaimSources(ctx context.Context, site siteState, rows []disclosure.RequiredCaseInspection, now domain.Time) (requiredHoldSourceSnapshots, domain.Time, error) {
	result := requiredHoldSourceSnapshots{}
	activations, e := requiredHoldActivations(r.site.State(), site)
	if e != nil {
		return result, 0, e
	}
	if e = inspectRequiredHoldParent(r.cfg.DataDir, activations, true); e != nil {
		return result, 0, e
	}
	var floor domain.Time
	for id, a := range activations {
		i, e := r.requiredReclaimSource(ctx, id, a, rows, site.MinimumReader, now)
		if e != nil {
			return result, 0, e
		}
		floor = max(floor, i.Floor)
		result.Receipts = append(result.Receipts, i.Receipts...)
		result.Renewals = append(result.Renewals, i.Renewals...)
	}
	return result, floor, nil
}

func (r *Repository) requiredReclaimSource(ctx context.Context, id domain.ID, activation requiredHoldActivation, rows []disclosure.RequiredCaseInspection, reader uint32, now domain.Time) (app.RequiredHoldsInspection, error) {
	b := r.posting[id]
	if b == nil {
		return app.RequiredHoldsInspection{}, store.ErrIncomplete
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		if activation.Phase == "active" && b.requiredHolds == nil {
			return app.RequiredHoldsInspection{}, store.ErrIncomplete
		}
		i, e := inspectRequiredHoldSource(r.cfg.DataDir, id, activation, b.key, true, reader, now)
		if e != nil {
			return i, e
		}
		return i, inspectRequiredHeldOriginalsWithCases(r.cfg.DataDir, b.key, i.Receipts, rows, now)
	})
	if e != nil {
		return app.RequiredHoldsInspection{}, e
	}
	return value.(app.RequiredHoldsInspection), nil
}

// reclaimRequiredOriginalsOwned は完了正本/独立carryを確認して共通容量を予約する。
func (r *Repository) reclaimRequiredOriginalsOwned(ctx context.Context, b *postingBoard, key, day uint64, candidates []evidence.RequiredPostingIdentity, guard *disclosure.RequiredGCProtection, now domain.Time) (int, error) {
	p, j, e := b.requiredReclaimPosting(key, day)
	if e != nil {
		return 0, e
	}
	if e = b.checkRequiredReclaimClock(now); e != nil {
		return 0, e
	}
	if e := b.checkRequiredReclaimTask(key, p); e != nil {
		return 0, e
	}
	bytes, e := j.RequiredPruneReservationBytes()
	if e != nil {
		return 0, e
	}
	release, e := r.reservePrivateReclaimBytes(bytes)
	if e != nil {
		return 0, e
	}
	defer release()
	journals := make([]*evidence.Journal, 0, len(b.journals))
	for _, source := range b.journals {
		journals = append(journals, source)
	}
	held := func(i evidence.RequiredPostingIdentity, at domain.Time) (bool, error) {
		return guard.PairHeld(b.owner, i, at)
	}
	n, e := p.PruneRequiredOriginalBatch(ctx, journals, j, candidates, now, b.key.Public().(ed25519.PublicKey), held)
	if e != nil && p.StorageStopped() {
		b.stopped = true
	}
	return n, e
}

// checkRequiredReclaimClock は別キー/別日の既存回収時刻も板全体の時計床として維持する。
func (b *postingBoard) checkRequiredReclaimClock(now domain.Time) error {
	for _, j := range b.journals {
		floor, e := j.RequiredRetirementFloor()
		if e != nil {
			return e
		}
		if now < floor {
			return evidence.ErrRetirementClock
		}
	}
	return nil
}

func (b *postingBoard) requiredReclaimPosting(key, day uint64) (*app.PostingLog, *evidence.Journal, error) {
	p, j := b.threads[key], b.journals[day]
	if b.stopped || !b.bodyReclaimEnabled || p == nil || j == nil {
		return nil, nil, store.ErrIncomplete
	}
	return p, j, nil
}

func (b *postingBoard) checkRequiredReclaimTask(key uint64, p *app.PostingLog) error {
	log := b.deletions[key]
	if log == nil {
		return store.ErrIncomplete
	}
	state, e := b.requiredReclaimPhysicalState(key, log)
	if e != nil {
		return e
	}
	proof, e := readBodyReclamation(state, b.owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil {
		return errors.Join(store.ErrIncomplete, e)
	}
	task, e := bodyTask(state, proof.Deletion)
	if e != nil || task.State != "complete" {
		return errors.Join(store.ErrIncomplete, e)
	}
	if e = verifyBodyTask(state, task, p); e != nil {
		return e
	}
	carry, e := b.boundBodyCarry(state, *proof)
	if e != nil || carry == nil {
		return errors.Join(store.ErrIncomplete, e)
	}
	return p.RestoreBodyCarry(*carry, domain.Time(b.clock().UnixNano()), b.key.Public().(ed25519.PublicKey))
}

// requiredReclaimPhysicalState は独立保存先の現存と現在所有者の全値一致を非変更で確認する。
func (b *postingBoard) requiredReclaimPhysicalState(key uint64, log *store.ControlLog) (store.ControlState, error) {
	state, e := inspectDeletionControl(filepath.Join(b.root, "expiry", b.owner.String(), fmt.Sprint(key)), b.owner, key)
	if e != nil {
		return state, e
	}
	if !reflect.DeepEqual(state, log.State()) {
		return state, store.ErrCorrupt
	}
	return state, nil
}
