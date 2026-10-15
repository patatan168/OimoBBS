// 元所有列の署名済み受理両側を照合して固定予約を確定し、同じ集合だけ取得/解除する。
package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"slices"
)

// Reserve は全原本を照合してから予約をSyncする。初回は元6暦月期限内だけ受理する。
// 呼出元は案件intentを先に署名し、同じ板所有列で原本/GCと直列化する。
func (h *RequiredOriginalHolds) Reserve(binding RequiredHoldBinding, records []AcceptedEvidence, journals map[uint64]*evidence.Journal, now domain.Time) (RequiredHoldReceipt, error) {
	if e := h.checkClock(now); e != nil {
		return RequiredHoldReceipt{}, e
	}
	if !h.initialized || binding.Until <= now || !validRequiredHoldBinding(binding, h.board, now) {
		return RequiredHoldReceipt{}, store.ErrCorrupt
	}
	postings, e := h.selectPostings(binding, records, journals)
	if e != nil {
		return RequiredHoldReceipt{}, e
	}
	if old, exists, e := h.existingReservation(binding, postings); e != nil || exists {
		return old, e
	}
	return h.reserveNew(binding, postings, now)
}

func (h *RequiredOriginalHolds) existingReservation(b RequiredHoldBinding, postings []RequiredHeldPosting) (RequiredHoldReceipt, bool, error) {
	old, exists := h.holds[b.Case]
	if !exists {
		return old, false, nil
	}
	if old.State != "active" || old.Binding != b || !slices.Equal(old.Postings, postings) {
		return RequiredHoldReceipt{}, true, store.ErrCorrupt
	}
	old.Postings = slices.Clone(old.Postings)
	return old, true, nil
}

func (h *RequiredOriginalHolds) reserveNew(binding RequiredHoldBinding, postings []RequiredHeldPosting, now domain.Time) (RequiredHoldReceipt, error) {
	if len(h.holds) >= MaxRequiredHolds {
		return RequiredHoldReceipt{}, ErrEvidenceSelectionLimit
	}
	for _, p := range postings {
		if p.Identity.Committed > now || postRetention(p.Identity.Committed) <= now {
			return RequiredHoldReceipt{}, ErrEvidenceGap
		}
	}
	if e := h.append(requiredHoldPayload{Action: "reserve", At: now, Binding: &binding, Postings: postings}); e != nil {
		return RequiredHoldReceipt{}, e
	}
	r, _, e := h.Receipt(binding.Case)
	return r, e
}

func (h *RequiredOriginalHolds) selectPostings(binding RequiredHoldBinding, records []AcceptedEvidence, journals map[uint64]*evidence.Journal) ([]RequiredHeldPosting, error) {
	if len(records) == 0 || len(records) > MaxRequiredHoldPostings {
		return nil, ErrEvidenceSelectionLimit
	}
	postings := make([]RequiredHeldPosting, 0, len(records))
	for _, record := range records {
		p, e := h.postingFromRecord(record, journals)
		if e != nil {
			return nil, e
		}
		postings = append(postings, p)
	}
	slices.SortFunc(postings, func(a, b RequiredHeldPosting) int {
		return bytes.Compare(a.Identity.ProposalID[:], b.Identity.ProposalID[:])
	})
	if e := validateRequiredHeldPostings(binding, postings); e != nil {
		return nil, e
	}
	return postings, nil
}

func (h *RequiredOriginalHolds) postingFromRecord(record AcceptedEvidence, journals map[uint64]*evidence.Journal) (RequiredHeldPosting, error) {
	var p RequiredHeldPosting
	var e error
	if record.Board != h.board {
		return p, ErrEvidenceGap
	}
	p.Proposal, e = h.sourceOf(record.Proposal)
	if e != nil {
		return p, e
	}
	p.Decision, e = h.sourceOf(record.Decision)
	if e != nil {
		return p, e
	}
	proposal, e := h.sourceEntry(p.Proposal, record.Proposal.Event.RecordID, record.Proposal.Event.EventSHA, journals)
	if e != nil {
		return p, e
	}
	decision, e := h.sourceEntry(p.Decision, record.Decision.Event.RecordID, record.Decision.Event.EventSHA, journals)
	if e != nil {
		return p, e
	}
	p.Identity, e = PostingRetirementIdentity(proposal, decision)
	if e != nil {
		return p, e
	}
	if !requiredRecordMatches(record, p.Identity) {
		return p, ErrEvidenceGap
	}
	actual, e := requiredAcceptedPair(h.board, p.Identity, proposal, decision)
	if e != nil || actual.Post != record.Post {
		return p, ErrEvidenceGap
	}
	return p, nil
}

// Fetch は現在予約の固定原本だけを返す。原期限満了後も有効予約で保護された実原本を照合する。
func (h *RequiredOriginalHolds) Fetch(expected RequiredHoldReceipt, journals map[uint64]*evidence.Journal, now domain.Time) ([]AcceptedEvidence, error) {
	if e := h.checkClock(now); e != nil {
		return nil, e
	}
	current, exists := h.holds[expected.Binding.Case]
	if !exists || current.State != "active" || current.Binding.Until <= now || !sameRequiredHoldReceipt(current, expected) {
		return nil, ErrEvidenceGap
	}
	rows := make([]AcceptedEvidence, 0, len(current.Postings))
	total := 0
	for _, p := range current.Postings {
		r, e := h.fetchPosting(p, journals)
		if e != nil {
			return nil, e
		}
		raw, e := json.Marshal(r)
		if e != nil {
			return nil, e
		}
		total += len(raw)
		if total > 64<<20 {
			return nil, ErrEvidenceSelectionLimit
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func (h *RequiredOriginalHolds) fetchPosting(p RequiredHeldPosting, journals map[uint64]*evidence.Journal) (AcceptedEvidence, error) {
	proposal, e := h.sourceEntry(p.Proposal, p.Identity.ProposalID, p.Identity.ProposalSHA, journals)
	if e != nil {
		return AcceptedEvidence{}, e
	}
	decision, e := h.sourceEntry(p.Decision, p.Identity.DecisionID, p.Identity.DecisionSHA, journals)
	if e != nil {
		return AcceptedEvidence{}, e
	}
	actual, e := PostingRetirementIdentity(proposal, decision)
	if e != nil || actual != p.Identity {
		return AcceptedEvidence{}, ErrEvidenceGap
	}
	return requiredAcceptedPair(h.board, actual, proposal, decision)
}

func requiredAcceptedPair(board domain.ID, i evidence.RequiredPostingIdentity, proposal, decision evidence.Entry) (AcceptedEvidence, error) {
	var p postingProposal
	if json.Unmarshal(proposal.Payload, &p) != nil {
		return AcceptedEvidence{}, ErrEvidenceGap
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
	if e != nil {
		return AcceptedEvidence{}, e
	}
	_, op, e := postingFrame(raw)
	if e != nil || op.Dedup == nil {
		return AcceptedEvidence{}, ErrEvidenceGap
	}
	return AcceptedEvidence{RecordID: i.ProposalID, Board: board, Thread: i.ThreadKey, Operation: i.OperationID, Post: op.Dedup.PostNumber, Committed: i.Committed, Expires: postRetention(i.Committed), Proposal: proposal, Decision: decision}, nil
}

func requiredRecordMatches(r AcceptedEvidence, i evidence.RequiredPostingIdentity) bool {
	return r.RecordID == i.ProposalID && r.Thread == i.ThreadKey && r.Operation == i.OperationID && r.Committed == i.Committed && r.Expires == postRetention(i.Committed)
}

func (h *RequiredOriginalHolds) sourceOf(entry evidence.Entry) (RequiredHoldSource, error) {
	var src struct {
		Owner    domain.ID  `json:"source_owner_id"`
		Day      domain.U64 `json:"source_subkey"`
		Sequence domain.U64 `json:"source_control_seq"`
	}
	if json.Unmarshal(entry.Payload, &src) != nil || src.Owner != h.board || src.Sequence == 0 {
		return RequiredHoldSource{}, ErrEvidenceGap
	}
	if _, e := evidence.Verify(evidence.Source{Owner: h.board, Subkey: uint64(src.Day), Seq: uint64(src.Sequence)}, entry.Event, entry.Event.PreviousSHA, h.keyID, h.public); e != nil {
		return RequiredHoldSource{}, e
	}
	if !retirementEntryMatches(entry) {
		return RequiredHoldSource{}, ErrEvidenceGap
	}
	return RequiredHoldSource{Day: src.Day, Sequence: src.Sequence}, nil
}

func (h *RequiredOriginalHolds) sourceEntry(src RequiredHoldSource, id domain.ID, sha domain.Hash, journals map[uint64]*evidence.Journal) (evidence.Entry, error) {
	j := journals[uint64(src.Day)]
	if j == nil || j.Owner() != h.board {
		return evidence.Entry{}, ErrEvidenceGap
	}
	entry, exists, e := j.Lookup(id)
	if e != nil {
		return evidence.Entry{}, e
	}
	if !exists || entry.Event.EventSHA != sha {
		return evidence.Entry{}, ErrEvidenceGap
	}
	actual, e := h.sourceOf(entry)
	if e != nil || actual != src {
		return evidence.Entry{}, ErrEvidenceGap
	}
	return entry, nil
}

// Release は現在予約の全固定参照を照合して署名解除する。満了後も可能で原本は再作成しない。
func (h *RequiredOriginalHolds) Release(expected RequiredHoldReceipt, now domain.Time) (RequiredHoldReceipt, error) {
	if e := h.checkClock(now); e != nil {
		return RequiredHoldReceipt{}, e
	}
	current, exists := h.holds[expected.Binding.Case]
	if !exists || !sameRequiredHoldReceipt(current, expected) {
		return RequiredHoldReceipt{}, store.ErrCorrupt
	}
	if current.State == "released" {
		return current, nil
	}
	binding := current.Binding
	if e := h.append(requiredHoldPayload{Action: "release", At: now, Binding: &binding, ExpectedSequence: current.Sequence, ExpectedSHA: current.SHA, Postings: slices.Clone(current.Postings)}); e != nil {
		return RequiredHoldReceipt{}, e
	}
	r, _, e := h.Receipt(binding.Case)
	return r, e
}

func sameRequiredHoldReceipt(a, b RequiredHoldReceipt) bool {
	return a.Binding == b.Binding && a.Sequence == b.Sequence && a.SHA == b.SHA && a.At == b.At && a.State == b.State && slices.Equal(a.Postings, b.Postings)
}
