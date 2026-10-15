// 一回128原本までの回収を、公開回収証明・固定受理対応・両側保護・稼働中復旧へ接続する。
package app

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// PruneRequiredOriginalBatch は最大64操作の一日列を回収し、原本mapを本文なしへ更新する。
// 全Journalと署名照合済み固定対応を渡す。heldPairは全集合の案件/元予約を両側で検査する。
// 呼出元はsite reader、空き容量、時計床を確認し、案件/板共通排他を保持する。
// 受理組には公開回収完了、未受理組にはreader52と7日接続記録の先行保存が必要。
// 事前検査失敗は非変更。回収保存/再構築の不確定時は所有者を停止して復旧へ渡す。
func (p *PostingLog) PruneRequiredOriginalBatch(ctx context.Context, journals []*evidence.Journal, journal *evidence.Journal, candidates []evidence.RequiredPostingIdentity, now domain.Time, public ed25519.PublicKey, heldPair func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (int, error) {
	if journal == nil || journal.Owner() != p.owner || heldPair == nil || len(candidates) == 0 || len(candidates) > 64 {
		return 0, store.ErrCorrupt
	}
	if e := p.checkOriginalBatchReclamation(ctx, candidates, now, public); e != nil {
		return 0, e
	}
	selected, e := p.requiredOriginalCandidates(journals, journal, candidates, now)
	if e != nil {
		return 0, e
	}
	unprotected, e := unprotectedOriginalCandidates(candidates, now, heldPair)
	if e != nil {
		return 0, e
	}
	if e := p.preserveRejectedConnections(journals, unprotected, now); e != nil {
		return 0, e
	}
	choose := func(entry evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
		return chooseRequiredOriginal(ctx, selected, entry, now, heldPair)
	}
	// 両側の予約はchooseで一括照合し、Journalの片側callbackでは追加しない。
	n, e := journal.PruneRequired(now, choose, func(domain.ID, domain.Time) (bool, error) { return false, nil }, nil)
	if e != nil {
		p.stopWriter()
		return 0, e
	}
	if n != 0 {
		e = p.reloadOriginalBatch(ctx, journals, candidates, now, public)
	}
	return n, e
}

// chooseRequiredOriginal は保存前の候補走査で取消と両側保護を確認する。
func chooseRequiredOriginal(ctx context.Context, selected map[domain.ID]evidence.RequiredPostingIdentity, entry evidence.Entry, now domain.Time, heldPair func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (*evidence.RequiredPostingIdentity, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	i, ok := selected[entry.Event.RecordID]
	if !ok {
		return nil, nil
	}
	held, e := heldPair(i, now)
	if e != nil || held {
		return nil, e
	}
	return &i, nil
}

func (p *PostingLog) requiredOriginalCandidates(journals []*evidence.Journal, target *evidence.Journal, candidates []evidence.RequiredPostingIdentity, now domain.Time) (map[domain.ID]evidence.RequiredPostingIdentity, error) {
	seen := map[*evidence.Journal]bool{}
	for _, j := range journals {
		if j == nil || j.Owner() != p.owner || seen[j] {
			return nil, ErrEvidenceGap
		}
		seen[j] = true
	}
	if !seen[target] || !seen[p.active] {
		return nil, ErrEvidenceGap
	}
	result := map[domain.ID]evidence.RequiredPostingIdentity{}
	for _, i := range candidates {
		if e := p.checkRequiredOriginalCandidate(journals, i, now); e != nil {
			return nil, e
		}
		if e := addOriginalCandidate(result, i); e != nil {
			return nil, e
		}
	}
	return result, nil
}

func addOriginalCandidate(result map[domain.ID]evidence.RequiredPostingIdentity, i evidence.RequiredPostingIdentity) error {
	if _, exists := result[i.ProposalID]; exists {
		return ErrEvidenceGap
	}
	if _, exists := result[i.DecisionID]; exists {
		return ErrEvidenceGap
	}
	result[i.ProposalID], result[i.DecisionID] = i, i
	return nil
}

// checkRequiredOriginalCandidate は原本または既に署名回収された片側から固定対応を検査する。
func (p *PostingLog) checkRequiredOriginalCandidate(journals []*evidence.Journal, i evidence.RequiredPostingIdentity, now domain.Time) error {
	if !p.originalCandidateScope(i, now) {
		return ErrEvidenceGap
	}
	a, aok, e := findOriginalCandidate(journals, i.ProposalID)
	if e != nil {
		return e
	}
	b, bok, e := findOriginalCandidate(journals, i.DecisionID)
	if e != nil {
		return e
	}
	if aok && bok {
		actual, e := PostingRetirementIdentity(a, b)
		if e != nil || actual != i {
			return ErrEvidenceGap
		}
		return nil
	}
	return p.checkPartiallyRetiredCandidate(i, a, aok, b, bok)
}

func (p *PostingLog) originalCandidateScope(i evidence.RequiredPostingIdentity, now domain.Time) bool {
	if i.ThreadKey != domain.U64(p.key) || evidence.RequiredOriginalDeadline(i, postRetention(i.Committed)) > now {
		return false
	}
	if i.Outcome == "not_accepted" {
		return !p.operationWritten(i.OperationID)
	}
	return i.Outcome == "accepted" && p.reclaimed != nil && p.originalCandidateInReclamation(i)
}

// originalCandidateInReclamation は公開回収証明の全操作集合から漏れた原本を回収しない。
func (p *PostingLog) originalCandidateInReclamation(i evidence.RequiredPostingIdentity) bool {
	for _, r := range p.reclaimed.records {
		if r.ID == i.OperationID {
			return r.Seq == i.ThreadSeq && r.FrameSHA == i.FrameSHA && r.Type == i.Type && r.Committed == i.Committed
		}
	}
	return false
}

func findOriginalCandidate(journals []*evidence.Journal, id domain.ID) (evidence.Entry, bool, error) {
	var result evidence.Entry
	found := false
	for _, j := range journals {
		entry, ok, e := j.Lookup(id)
		if e != nil {
			return result, false, e
		}
		if ok {
			if found {
				return result, false, ErrEvidenceGap
			}
			result, found = entry, true
		}
	}
	return result, found, nil
}

func (p *PostingLog) checkPartiallyRetiredCandidate(i evidence.RequiredPostingIdentity, a evidence.Entry, aok bool, b evidence.Entry, bok bool) error {
	r, exists := p.retired[i.OperationID]
	if !exists || r.identity != i || (r.proposal == nil) != aok || (r.decision == nil) != bok {
		return ErrEvidenceGap
	}
	if !originalCandidateSideMatches(a, aok, "evidence_proposal", i.ProposalSHA) {
		return ErrEvidenceGap
	}
	if !originalCandidateSideMatches(b, bok, "evidence_decision", i.DecisionSHA) {
		return ErrEvidenceGap
	}
	return nil
}

func originalCandidateSideMatches(entry evidence.Entry, present bool, kind string, sha domain.Hash) bool {
	return !present || entry.Event.Kind == kind && entry.Event.EventSHA == sha
}

// unprotectedOriginalCandidates は元への追加保存前に両側保全の読取り失敗も確認する。
func unprotectedOriginalCandidates(candidates []evidence.RequiredPostingIdentity, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) ([]evidence.RequiredPostingIdentity, error) {
	result := []evidence.RequiredPostingIdentity{}
	for _, i := range candidates {
		protected, e := held(i, now)
		if e != nil {
			return nil, e
		}
		if !protected {
			result = append(result, i)
		}
	}
	return result, nil
}
