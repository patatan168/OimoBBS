// 回収済み公開所有者の操作列を最大64行ずつ走査し、原本回収の固定候補を選ぶ。
package app

import (
	"encoding/base64"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"sort"
)

// RequiredOriginalScan は走査位置と本文を含まない固定受理対応。
// Doneは操作列末尾であり、保全中原本や全保存コピーの回収完了ではない。
type RequiredOriginalScan struct {
	Next       domain.U64
	Done       bool
	Candidates []evidence.RequiredPostingIdentity
}

// ScanRequiredOriginals はafterより後の最大limit操作を走査する。limitは1..64。
// 非受理/管理操作・未満了・両側回収済みも走査位置を進め、同じ先頭へ滞留しない。
// 原本の署名/固定対応は全Journalから確認し、本文を候補へコピーしない。
// エラー時のNextは採用せず、再開時は元の走査位置を使う。
func (p *PostingLog) ScanRequiredOriginals(journals []*evidence.Journal, after domain.U64, limit int, now domain.Time) (RequiredOriginalScan, error) {
	result := RequiredOriginalScan{Next: after, Candidates: []evidence.RequiredPostingIdentity{}}
	if p.stopped || p.reclaimed == nil || limit < 1 || limit > 64 {
		return result, ErrEvidenceGap
	}
	records := p.reclaimed.records
	start := sort.Search(len(records), func(i int) bool { return records[i].Seq > after })
	end := min(len(records), start+limit)
	selected := map[domain.ID]bool{}
	for _, record := range records[start:end] {
		result.Next = record.Seq
		if record.Type == "create" || record.Type == "append" {
			if postRetention(record.Committed) <= now && !p.originalPairRetired(record.ID) {
				selected[record.ID] = true
			}
		}
	}
	result.Done = end == len(records)
	var e error
	result.Candidates, e = p.requiredScanIdentities(journals, records[start:end], selected, now)
	return result, e
}

func (p *PostingLog) originalPairRetired(id domain.ID) bool {
	r, ok := p.retired[id]
	return ok && r.proposal != nil && r.decision != nil
}

// requiredScanIdentities は固定順を保ち、部分回収対応と通常両原本を同じ候補へまとめる。
func (p *PostingLog) requiredScanIdentities(journals []*evidence.Journal, records []store.ThreadRecord, selected map[domain.ID]bool, now domain.Time) ([]evidence.RequiredPostingIdentity, error) {
	identities, e := p.requiredScanDecisions(journals, selected)
	if e != nil {
		return nil, e
	}
	result := []evidence.RequiredPostingIdentity{}
	for _, record := range records {
		if !selected[record.ID] {
			continue
		}
		i, ok := identities[record.ID]
		if !ok || !p.originalCandidateScope(i, now) {
			return nil, ErrEvidenceGap
		}
		if e := p.checkRequiredOriginalCandidate(journals, i, now); e != nil {
			return nil, e
		}
		result = append(result, i)
	}
	return result, nil
}

func (p *PostingLog) requiredScanDecisions(journals []*evidence.Journal, selected map[domain.ID]bool) (map[domain.ID]evidence.RequiredPostingIdentity, error) {
	result := map[domain.ID]evidence.RequiredPostingIdentity{}
	pending := map[domain.ID]bool{}
	for id := range selected {
		if r, ok := p.retired[id]; ok {
			result[id] = r.identity
		} else {
			pending[id] = true
		}
	}
	if len(pending) == 0 {
		return result, nil
	}
	for _, j := range journals {
		if j == nil || j.Owner() != p.owner {
			return nil, ErrEvidenceGap
		}
		if e := j.Visit(func(entry evidence.Entry) error { return p.addRequiredScanDecision(entry, pending, result) }); e != nil {
			return nil, e
		}
	}
	return result, nil
}

func (p *PostingLog) addRequiredScanDecision(entry evidence.Entry, pending map[domain.ID]bool, result map[domain.ID]evidence.RequiredPostingIdentity) error {
	if entry.Event.Kind != "evidence_decision" {
		return nil
	}
	var d postingDecision
	if e := strictjson.Decode(entry.Payload, &d); e != nil {
		return e
	}
	if !pending[d.OperationID] {
		return nil
	}
	if _, duplicate := result[d.OperationID]; duplicate {
		return ErrEvidenceGap
	}
	proposal, ok := p.proposals[d.OperationID]
	if !ok {
		return ErrEvidenceGap
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(proposal.event.Payload)
	if e != nil {
		return ErrEvidenceGap
	}
	i, e := PostingRetirementIdentity(evidence.Entry{Event: proposal.event, Payload: raw}, entry)
	if e != nil || i.Outcome != "accepted" {
		return ErrEvidenceGap
	}
	result[d.OperationID] = i
	return nil
}
