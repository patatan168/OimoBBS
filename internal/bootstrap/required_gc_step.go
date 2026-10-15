// 保存済み操作窓の一日列だけを回収し、完了後にだけ耐久cursorを進める。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// runRequiredGCJobLocked は現在の全保全対応を確認し、所有列の回収または次scope選択を行う。
func (r *Repository) runRequiredGCJobLocked(ctx context.Context, site siteState, v requiredGCState, now time.Time) (requiredGCState, int, error) {
	v.At = domain.Time(now.UnixNano())
	guard, e := r.requiredReclaimProtection(ctx, site, now)
	if e != nil {
		return v, 0, e
	}
	if v.Board == nil || v.Advance {
		next, _, e := r.nextRequiredGCScope(ctx, v)
		return next, 0, e
	}
	b := r.posting[v.boardID()]
	if b == nil {
		return v, 0, store.ErrIncomplete
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		next, removed, e := r.stepRequiredGCJobOwned(ctx, b, v, guard)
		return requiredGCStepResult{next, removed}, e
	})
	if e != nil {
		return v, 0, e
	}
	result := value.(requiredGCStepResult)
	return result.state, result.removed, nil
}

type requiredGCStepResult struct {
	state   requiredGCState
	removed int
}

// stepRequiredGCJobOwned は64操作窓の次の日別列だけを回収し、成功後の位置を返す。
func (r *Repository) stepRequiredGCJobOwned(ctx context.Context, b *postingBoard, v requiredGCState, guard *disclosure.RequiredGCProtection) (requiredGCState, int, error) {
	p, ready, e := b.requiredGCBodyReady(ctx, v)
	if e != nil {
		return v, 0, e
	}
	if !ready {
		v.Advance = true
		return v, 0, nil
	}
	proof, e := b.requiredGCProof(v)
	if e != nil {
		return v, 0, e
	}
	v.Proof = proof
	journals := requiredGCJournals(b)
	scan, e := p.ScanRequiredOriginals(journals, v.After, 64, v.At)
	if e != nil {
		return v, 0, e
	}
	day, e := nextRequiredGCSourceDay(b, v.Day, scan.Candidates)
	if e != nil {
		return v, 0, e
	}
	if day == 0 {
		v.After, v.Day, v.Advance = scan.Next, 0, scan.Done
		return v, 0, nil
	}
	n, e := r.reclaimRequiredOriginalsOwned(ctx, b, uint64(v.Key), uint64(day), scan.Candidates, guard, v.At)
	if e != nil {
		return v, n, e
	}
	v.Day = day
	return v, n, nil
}

func (b *postingBoard) requiredGCBodyReady(ctx context.Context, v requiredGCState) (*app.PostingLog, bool, error) {
	p := b.threads[uint64(v.Key)]
	if b.stopped || p == nil {
		return p, false, store.ErrIncomplete
	}
	if e := b.checkRequiredReclaimClock(v.At); e != nil {
		return p, false, e
	}
	if !p.Reclaimed() {
		return p, false, nil
	}
	if e := b.checkRequiredReclaimTask(uint64(v.Key), p); e != nil {
		return p, false, e
	}
	e := p.CheckRequiredOriginalReclamation(ctx, v.At, b.key.Public().(ed25519.PublicKey))
	return p, e == nil, e
}

func (b *postingBoard) requiredGCProof(v requiredGCState) (domain.Hash, error) {
	key, expected := uint64(v.Key), v.Proof
	log := b.deletions[key]
	if log == nil {
		return domain.Hash{}, store.ErrIncomplete
	}
	proof, e := readBodyReclamation(log.State(), b.owner, key, b.key.Public().(ed25519.PublicKey))
	if e != nil || proof == nil {
		return domain.Hash{}, errors.Join(store.ErrCorrupt, e)
	}
	digest := reclamationDigest(*proof)
	if expected != (domain.Hash{}) && expected != digest {
		return domain.Hash{}, store.ErrCorrupt
	}
	if v.After > proof.Sequence || v.Day != 0 && b.journals[uint64(v.Day)] == nil {
		return domain.Hash{}, store.ErrCorrupt
	}
	return digest, nil
}

func requiredGCJournals(b *postingBoard) []*evidence.Journal {
	days := make([]uint64, 0, len(b.journals))
	for day := range b.journals {
		days = append(days, day)
	}
	slices.Sort(days)
	result := make([]*evidence.Journal, 0, len(days))
	for _, day := range days {
		result = append(result, b.journals[day])
	}
	return result
}

func nextRequiredGCSourceDay(b *postingBoard, after domain.U64, candidates []evidence.RequiredPostingIdentity) (domain.U64, error) {
	ids := map[domain.ID]bool{}
	for _, i := range candidates {
		ids[i.ProposalID], ids[i.DecisionID] = true, true
	}
	var result domain.U64
	for day, j := range b.journals {
		d := domain.U64(day)
		if d <= after || result != 0 && d >= result {
			continue
		}
		found, e := requiredGCSourceMatches(j, ids)
		if e != nil {
			return 0, e
		}
		if found {
			result = d
		}
	}
	return result, nil
}

var errRequiredGCSourceFound = errors.New("required GC source matched")

func requiredGCSourceMatches(j *evidence.Journal, ids map[domain.ID]bool) (bool, error) {
	e := j.Visit(func(entry evidence.Entry) error {
		if ids[entry.Event.RecordID] {
			return errRequiredGCSourceFound
		}
		return nil
	})
	if errors.Is(e, errRequiredGCSourceFound) {
		return true, nil
	}
	return false, e
}
