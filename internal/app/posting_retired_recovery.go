// 必須原本の回収証跡と公開回収証明を結び、本文なし状態だけを復旧する。
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"sort"
)

type retiredPostingOriginals struct {
	identity evidence.RequiredPostingIdentity
	proposal *evidence.RequiredRetirement
	decision *evidence.RequiredRetirement
}

// OpenPostingWithRetiredOriginals は回収済み必須原本を持つキーを本文なしで復旧する。
// 署名済み公開回収証明と独立carryを必須とし、原本回収のない通常Openとは分ける。
// 元本文・接続情報・元署名payloadを再作成せず、公開/投稿は常に期限切れとして拒否する。
func OpenPostingWithRetiredOriginals(parent string, owner domain.ID, key uint64, journals []*evidence.Journal, active *evidence.Journal, now domain.Time, proof BodyReclamation, carry *BodyCarry, public ed25519.PublicKey) (*PostingLog, error) {
	if owner == (domain.ID{}) || key == 0 || active == nil || active.Owner() != owner || carry == nil {
		return nil, ErrEvidenceGap
	}
	p := &PostingLog{parent: parent, owner: owner, key: key, active: active, proposals: map[domain.ID]proposalEntry{}, retired: map[domain.ID]retiredPostingOriginals{}}
	entries, e := p.loadRetiredJournals(journals)
	if e != nil {
		return nil, e
	}
	if len(p.retired) == 0 {
		return nil, ErrEvidenceGap
	}
	if now < p.retiredFloor {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceGap, evidence.ErrRetirementClock)
	}
	for _, v := range p.retired {
		if !retirementTimeValid(v, proof, now) {
			return nil, ErrEvidenceGap
		}
	}
	decisions, e := p.loadEntries(entries)
	if e != nil {
		return nil, e
	}
	if e = p.openRetiredReclamation(proof, carry, decisions, now, public); e != nil {
		return nil, e
	}
	if e = store.CheckReclaimedBody(context.Background(), filepath.Join(parent, fmt.Sprint(key)), proof.Files); e != nil {
		return nil, e
	}
	return p, nil
}

// loadRetiredJournals は検証済み全期間列を集め、同一操作の削除証跡を一つの固定対応へ照合する。
func (p *PostingLog) loadRetiredJournals(journals []*evidence.Journal) ([]evidence.Entry, error) {
	entries := []evidence.Entry{}
	if p.retired == nil {
		p.retired = map[domain.ID]retiredPostingOriginals{}
	}
	seen := map[*evidence.Journal]bool{}
	for _, j := range journals {
		if j == nil || j.Owner() != p.owner || seen[j] {
			return nil, ErrEvidenceGap
		}
		seen[j] = true
		floor, e := j.RequiredRetirementFloor()
		if e != nil {
			return nil, e
		}
		if floor > p.retiredFloor {
			p.retiredFloor = floor
		}
		retirements, e := j.RequiredRetirements()
		if e != nil {
			return nil, e
		}
		for _, r := range retirements {
			if r.Envelope.Kind != rejectedConnectionKind && r.Identity.ThreadKey == domain.U64(p.key) {
				if e = p.addRetiredOriginal(r); e != nil {
					return nil, e
				}
			}
		}
		for _, entry := range j.Entries() {
			if entry.Event.Kind != "tombstone" {
				entries = append(entries, entry)
				continue
			}
			var marker struct {
				Reason string `json:"reason"`
			}
			if json.Unmarshal(entry.Payload, &marker) != nil || !evidence.RequiredRetirementReason(marker.Reason) {
				return nil, ErrEvidenceGap
			}
		}
	}
	if !seen[p.active] {
		return nil, ErrEvidenceGap
	}
	return entries, nil
}

// addRetiredOriginal は同一操作の両原本の対応差替え・重複回収を拒否する。
func (p *PostingLog) addRetiredOriginal(r evidence.RequiredRetirement) error {
	i := r.Identity
	v, found := p.retired[i.OperationID]
	if found && v.identity != i {
		return ErrEvidenceGap
	}
	v.identity = i
	switch r.Envelope.Kind {
	case "evidence_proposal":
		if v.proposal != nil {
			return ErrEvidenceGap
		}
		v.proposal = &r
	case "evidence_decision":
		if v.decision != nil {
			return ErrEvidenceGap
		}
		v.decision = &r
	default:
		return ErrEvidenceGap
	}
	p.retired[i.OperationID] = v
	return nil
}

// restoreRetiredEntries は実原本が存在する側を照合し、削除済み側だけを内部復旧対応へ変換する。
// この内部型は元の署名payloadではなく、Journalや提供照会へ書き戻さない。
func (p *PostingLog) restoreRetiredEntries(decisions map[domain.ID]postingDecision, kinds map[domain.ID]string, events map[domain.ID]evidence.Event) error {
	for id, v := range p.retired {
		if e := p.restoreRetiredProposal(id, v); e != nil {
			return e
		}
		d, exists := decisions[id]
		if v.decision == nil {
			if !exists || events[id].Kind != "evidence_decision" || events[id].RecordID != v.identity.DecisionID || events[id].EventSHA != v.identity.DecisionSHA || !d.matches(p.proposals[id].payload, p.proposals[id].event) || d.Outcome != v.identity.Outcome {
				return ErrEvidenceGap
			}
			continue
		}
		if exists {
			return ErrEvidenceGap
		}
		i := v.identity
		decisions[id] = postingDecision{Owner: p.owner, Seq: v.decision.Seq, ThreadKey: i.ThreadKey, OperationID: id, ThreadSeq: i.ThreadSeq, FrameSHA: i.FrameSHA, ProposalID: i.ProposalID, ProposalSHA: i.ProposalSHA, Committed: i.Committed, Retention: postRetention(i.Committed), Outcome: i.Outcome}
		kinds[id] = "evidence_decision"
	}
	return nil
}

// restoreRetiredProposal は残る完全proposalか回収済みの対応情報のどちらか一つだけを採用する。
func (p *PostingLog) restoreRetiredProposal(id domain.ID, v retiredPostingOriginals) error {
	entry, exists := p.proposals[id]
	i := v.identity
	if v.proposal != nil {
		if exists {
			return ErrEvidenceGap
		}
		p.proposals[id] = proposalEntry{payload: postingProposal{Owner: p.owner, Seq: v.proposal.Seq, ThreadKey: i.ThreadKey, OperationID: id, ThreadSeq: i.ThreadSeq, FrameSHA: i.FrameSHA, Committed: i.Committed, Retention: postRetention(i.Committed)}, event: v.proposal.Envelope}
		return nil
	}
	if !exists || entry.event.Kind != "evidence_proposal" || entry.event.RecordID != i.ProposalID || entry.event.EventSHA != i.ProposalSHA {
		return ErrEvidenceGap
	}
	if e := evidenceIdentityMatchesProposal(i, entry.payload); e != nil {
		return e
	}
	return nil
}

func evidenceIdentityMatchesProposal(i evidence.RequiredPostingIdentity, p postingProposal) error {
	if i.ThreadKey != p.ThreadKey || i.OperationID != p.OperationID || i.ThreadSeq != p.ThreadSeq || i.FrameSHA != p.FrameSHA || i.Committed != p.Committed {
		return ErrEvidenceGap
	}
	return nil
}

// openRetiredReclamation は元署名付き対応と公開回収証明のrecord集合を照合し、carryを先に検証する。
func (p *PostingLog) openRetiredReclamation(v BodyReclamation, carry *BodyCarry, decisions map[domain.ID]postingDecision, now domain.Time, public ed25519.PublicKey) error {
	if e := v.Verify(public); e != nil {
		return e
	}
	if v.Owner != p.owner || uint64(v.Key) != p.key {
		return ErrEvidenceGap
	}
	if carry.Retirement != nil {
		if e := carry.verifyRetirement(v, now, public); e != nil {
			return e
		}
	}
	records := []store.ThreadRecord{}
	for id, d := range decisions {
		entry, found := p.proposals[id]
		if !found || !d.matches(entry.payload, entry.event) {
			return ErrEvidenceGap
		}
		if d.Outcome != "accepted" {
			continue
		}
		r, e := p.retiredThreadRecord(id, entry)
		if e != nil {
			return e
		}
		records = append(records, r)
	}
	if uint64(len(records)) != uint64(v.Sequence) {
		return ErrEvidenceGap
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Seq < records[j].Seq })
	for index, r := range records {
		if r.Seq != domain.U64(index+1) {
			return ErrEvidenceGap
		}
	}
	if bodyRecordsSHA(records) != v.RecordsSHA {
		return ErrEvidenceGap
	}
	if e := checkRecoverableCarryCompleteness(records, v, carry, now, public); e != nil {
		return e
	}
	p.reclaimed = &reclaimedBody{proof: v, records: records}
	if e := p.RestoreBodyCarry(*carry, now, public); e != nil {
		return e
	}
	p.RestoreExpired()
	return p.reconcile(decisions, v.At)
}

// checkRecoverableCarryCompleteness は通常の全件照合と署名済み全件満了を分けて検査する。
func checkRecoverableCarryCompleteness(records []store.ThreadRecord, proof BodyReclamation, carry *BodyCarry, now domain.Time, public ed25519.PublicKey) error {
	if carry.Retirement != nil {
		return carry.verifyRetirement(proof, now, public)
	}
	return checkRetiredCarryCompleteness(records, proof, carry)
}

// checkRetiredCarryCompleteness は元schemaの捕捉境界に必要な全受理枠が揃うことを確認する。
func checkRetiredCarryCompleteness(records []store.ThreadRecord, proof BodyReclamation, carry *BodyCarry) error {
	available := map[domain.ID]bool{}
	for _, rate := range carry.Rates {
		available[rate.ID] = true
	}
	for _, record := range records {
		if record.Type != "create" && record.Type != "append" {
			continue
		}
		if !available[record.ID] {
			return ErrEvidenceGap
		}
	}
	return nil
}

// retiredThreadRecord は完全frameまたは回収済み署名対応から本文なしrecordを作る。
func (p *PostingLog) retiredThreadRecord(id domain.ID, entry proposalEntry) (store.ThreadRecord, error) {
	if v, found := p.retired[id]; found && v.proposal != nil {
		i := v.identity
		return store.ThreadRecord{ID: id, Seq: i.ThreadSeq, FrameSHA: i.FrameSHA, Type: i.Type, Committed: i.Committed}, nil
	}
	raw, e := entry.decodeFrame()
	if e != nil {
		return store.ThreadRecord{}, ErrEvidenceGap
	}
	var op domain.Operation
	if entry.event.Kind == "thread_admin_proposal" {
		_, op, e = administrativeFrame(raw)
	} else {
		_, op, e = postingFrame(raw)
	}
	if e != nil {
		return store.ThreadRecord{}, ErrEvidenceGap
	}
	return store.ThreadRecord{ID: id, Seq: entry.payload.ThreadSeq, FrameSHA: entry.payload.FrameSHA, Type: op.Type, Committed: entry.payload.Committed}, nil
}

// retiredRateRecord は検証済みcarryから受理枠だけを返す。元IP・Cookie/資格検証情報は復元しない。
// 原本由来の通常履歴と区別するschemaであり、製品の認可復旧側も明示対応が必要。
func (p *PostingLog) retiredRateRecord(record store.ThreadRecord, rate RateCarry, found bool) (RateRecord, error) {
	if p.reclaimed == nil || p.reclaimed.carry == nil || !found {
		return RateRecord{}, ErrEvidenceGap
	}
	i := p.retired[record.ID].identity
	if rate.ID != record.ID || rate.At != record.Committed || rate.Validate() != nil || i.FrameSHA != record.FrameSHA || i.ThreadSeq != record.Seq || i.Type != record.Type || i.Committed != record.Committed || i.Outcome != "accepted" {
		return RateRecord{}, ErrEvidenceGap
	}
	v := RateRecord{Schema: RetiredRateSchema, TokenStatus: "unavailable", ID: record.ID, PostNumber: rate.Number, At: rate.At, Create: record.Type == "create", Keys: append([]domain.RateKey{}, rate.Keys...)}
	pressureAt := domain.Time(0)
	if p.reclaimed.proof.Kind == "pressure" {
		pressureAt = p.reclaimed.proof.At
	}
	v.Retirement = &RateRetirementProof{pressureAt: pressureAt, owner: p.owner, key: p.key, until: postRetention(i.Committed), floor: p.retiredFloor, digest: rateRetirementDigest(v)}
	return v, nil
}

// retirementTimeValid は早期回収の印を署名済み公開証明に束縛する。通常満了の検査は緩めない。
func retirementTimeValid(v retiredPostingOriginals, proof BodyReclamation, now domain.Time) bool {
	pressure := v.proposal != nil && v.proposal.Pressure || v.decision != nil && v.decision.Pressure
	if pressure {
		return v.identity.Outcome == "accepted" && proof.Kind == "pressure" && proof.At <= now && v.identity.Committed <= proof.At
	}
	return evidence.RequiredOriginalDeadline(v.identity, postRetention(v.identity.Committed)) <= now
}
