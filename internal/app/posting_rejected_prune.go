// 確定未受理原本を既存の回収署名へ移し、公開所有者を維持して接続情報を解放する。
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// RejectedOriginalCandidates は24時間を過ぎた確定未受理の最大64組を選ぶ。
// 全期間の署名Journalを板排他内で渡す。保全中の組は飛ばし、未決定と受理原本は残す。
func (p *PostingLog) RejectedOriginalCandidates(journals []*evidence.Journal, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) ([]evidence.RequiredPostingIdentity, error) {
	if p.stopped || held == nil || now < p.retiredFloor {
		return nil, ErrEvidenceGap
	}
	result := []evidence.RequiredPostingIdentity{}
	seen := map[domain.ID]bool{}
	if e := p.addPartiallyRetiredRejections(now, held, seen, &result); e != nil {
		return nil, e
	}
	for _, j := range journals {
		if j == nil || j.Owner() != p.owner {
			return nil, ErrEvidenceGap
		}
		if e := j.Visit(func(entry evidence.Entry) error { return p.addRejectedEntry(entry, now, held, seen, &result) }); e != nil {
			return nil, e
		}
	}

	return result, nil
}

func (p *PostingLog) addRejectedCandidate(i evidence.RequiredPostingIdentity, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error), seen map[domain.ID]bool, result *[]evidence.RequiredPostingIdentity) error {
	if len(*result) == 64 || seen[i.OperationID] || i.Outcome != "not_accepted" || evidence.RequiredOriginalDeadline(i, postRetention(i.Committed)) > now {
		return nil
	}
	if !p.originalCandidateScope(i, now) {
		return ErrEvidenceGap
	}
	protected, e := held(i, now)
	if e != nil {
		return e
	}
	seen[i.OperationID] = true
	if !protected {
		*result = append(*result, i)
	}
	return nil
}

// operationWritten は公開WALまたは回収済み公開操作列の受理と未受理を取り違えない。
func (p *PostingLog) operationWritten(id domain.ID) bool {
	if p.thread == nil && p.reclaimed == nil {
		return false
	}
	for _, record := range p.records() {
		if record.ID == id {
			return true
		}
	}
	return false
}

func rejectedOriginalBatch(candidates []evidence.RequiredPostingIdentity) bool {
	for _, i := range candidates {
		if i.Outcome != "not_accepted" {
			return false
		}
	}
	return true
}

// checkOriginalBatchReclamation は未受理組には公開回収を要求せず、受理組の既存証明を維持する。
func (p *PostingLog) checkOriginalBatchReclamation(ctx context.Context, candidates []evidence.RequiredPostingIdentity, now domain.Time, public ed25519.PublicKey) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if p.stopped {
		return store.ErrIncomplete
	}
	if now < p.retiredFloor {
		return evidence.ErrRetirementClock
	}
	if rejectedOriginalBatch(candidates) {
		return nil
	}
	return p.CheckRequiredOriginalReclamation(ctx, now, public)
}

// reloadOriginalBatch は未受理原本の回収後も公開threadを保持し、原本を持つmapだけ置換する。
func (p *PostingLog) reloadOriginalBatch(ctx context.Context, journals []*evidence.Journal, candidates []evidence.RequiredPostingIdentity, now domain.Time, public ed25519.PublicKey) error {
	if !rejectedOriginalBatch(candidates) {
		return p.ReloadRetiredOriginals(ctx, journals, now, public)
	}
	next := &PostingLog{owner: p.owner, key: p.key, active: p.active, proposals: map[domain.ID]proposalEntry{}}
	entries, e := next.loadRetiredJournals(journals)
	if e == nil {
		var decisions map[domain.ID]postingDecision
		decisions, e = next.loadEntries(entries)
		if e == nil {
			next.thread, next.reclaimed = p.thread, p.reclaimed
			e = next.reconcile(decisions, now)
		}
	}
	if e != nil {
		p.stopWriter()
		return e
	}
	p.proposals, p.retired, p.retiredFloor = next.proposals, next.retired, next.retiredFloor
	return nil
}

// HasUnretiredRejections は未回収の非公開操作が存在する可能性を本文の走査なしで返す。
func (p *PostingLog) HasUnretiredRejections() bool {
	var sequence domain.U64
	if p.thread != nil {
		sequence = p.thread.State().Revision
	}
	if p.reclaimed != nil {
		sequence = p.reclaimed.proof.Sequence
	}
	retired := 0
	for _, r := range p.retired {
		if r.identity.Outcome == "not_accepted" && r.proposal != nil && r.decision != nil {
			retired++
		}
	}
	return uint64(len(p.proposals)-retired) > uint64(sequence)
}

// addPartiallyRetiredRejections は別日列や前回の有界回収で残った片側を候補へ含める。
func (p *PostingLog) addPartiallyRetiredRejections(now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error), seen map[domain.ID]bool, result *[]evidence.RequiredPostingIdentity) error {
	for _, r := range p.retired {
		if !p.originalPairRetired(r.identity.OperationID) {
			if e := p.addRejectedCandidate(r.identity, now, held, seen, result); e != nil {
				return e
			}
		}
	}
	return nil
}

func (p *PostingLog) addRejectedEntry(entry evidence.Entry, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error), seen map[domain.ID]bool, result *[]evidence.RequiredPostingIdentity) error {
	if entry.Event.Kind != "evidence_decision" {
		return nil
	}
	var d postingDecision
	if e := strictjson.Decode(entry.Payload, &d); e != nil {
		return e
	}
	if !p.rejectedDecisionCandidate(d, seen, len(*result)) {
		return nil
	}
	if r, ok := p.retired[d.OperationID]; ok {
		return p.addRejectedCandidate(r.identity, now, held, seen, result)
	}
	proposal, ok := p.proposals[d.OperationID]
	if !ok {
		return ErrEvidenceGap
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(proposal.event.Payload)
	if e != nil {
		return e
	}
	i, e := PostingRetirementIdentity(evidence.Entry{Event: proposal.event, Payload: raw}, entry)
	if e != nil {
		return e
	}
	return p.addRejectedCandidate(i, now, held, seen, result)
}

func (p *PostingLog) rejectedDecisionCandidate(d postingDecision, seen map[domain.ID]bool, count int) bool {
	return d.ThreadKey == domain.U64(p.key) && d.Outcome == "not_accepted" && !seen[d.OperationID] && count < 64
}
