// 必須原本予約の固定型・署名履歴順序と案件別CASを検証する。
package app

import (
	"encoding/json"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"strconv"
	"time"
)

// ValidateRequiredHoldReceipt は固定参照の完全型/範囲だけを検査する。署名/現在元は所有者が別に照合する。
func ValidateRequiredHoldReceipt(r RequiredHoldReceipt) error {
	if r.Sequence < 2 || r.SHA == (domain.Hash{}) || r.At <= 0 || r.State != "active" && r.State != "released" {
		return store.ErrCorrupt
	}
	if !validRequiredHoldBinding(r.Binding, r.Binding.Board, r.At) || r.Binding.Board == (domain.ID{}) {
		return store.ErrCorrupt
	}
	return validateRequiredHeldPostings(r.Binding, r.Postings)
}

func requiredHoldValidator(board domain.ID) evidence.PayloadValidator {
	return func(kind string, raw []byte) error {
		var p requiredHoldPayload
		if kind != "checkpoint" || len(raw) > 256<<10 || strictjson.Decode(raw, &p) != nil {
			return store.ErrCorrupt
		}
		return validateRequiredHoldPayload(board, p)
	}
}

func validateRequiredHoldPayload(board domain.ID, p requiredHoldPayload) error {
	if !validRequiredHoldHeader(board, p) || !validRequiredHoldSchema(p) {
		return store.ErrCorrupt
	}
	if (p.Sequence == 1) != (p.Action == "initialize") {
		return store.ErrCorrupt
	}
	if p.Action == "initialize" {
		if p.Binding != nil || len(p.Postings) != 0 || p.ExpectedSequence != 0 || p.ExpectedSHA != (domain.Hash{}) {
			return store.ErrCorrupt
		}
		return nil
	}
	return validateRequiredHoldChange(board, p)
}

func validRequiredHoldHeader(board domain.ID, p requiredHoldPayload) bool {
	return p.Board == board && p.Owner == requiredHoldsOwner(board) && p.Day == domain.U64(requiredHoldsDay) && p.Sequence > 0 && p.At > 0 && p.Postings != nil
}

func validateRequiredHoldChange(board domain.ID, p requiredHoldPayload) error {
	if p.Action != "reserve" && p.Action != "release" && p.Action != "renew" || p.Binding == nil || !validRequiredHoldBinding(*p.Binding, board, p.At) {
		return store.ErrCorrupt
	}
	if p.ExpectedSequence >= p.Sequence || (p.ExpectedSequence == 0) != (p.ExpectedSHA == (domain.Hash{})) {
		return store.ErrCorrupt
	}
	return validateRequiredHeldPostings(*p.Binding, p.Postings)
}

func validRequiredHoldBinding(b RequiredHoldBinding, board domain.ID, at domain.Time) bool {
	if b.Case == (domain.ID{}) || b.Revision == 0 || b.Board != board || b.From <= 0 || b.From >= b.To || b.Until <= 0 {
		return false
	}
	// 解除は期限後にも記録する。新規予約の現在期限はReserveで検査する。
	return at <= domain.Time(math.MaxInt64-int64(180*24*time.Hour)) && b.Until <= at+domain.Time(180*24*time.Hour)
}

func validateRequiredHeldPostings(b RequiredHoldBinding, postings []RequiredHeldPosting) error {
	if len(postings) == 0 || len(postings) > MaxRequiredHoldPostings {
		return store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, p := range postings {
		if e := validateRequiredHeldPosting(b, p); e != nil {
			return e
		}
		for _, id := range []domain.ID{p.Identity.ProposalID, p.Identity.DecisionID, p.Identity.OperationID} {
			if seen[id] {
				return store.ErrCorrupt
			}
			seen[id] = true
		}
	}
	return nil
}

func validateRequiredHeldPosting(b RequiredHoldBinding, p RequiredHeldPosting) error {
	i := p.Identity
	if i.Outcome != "accepted" || i.Committed < b.From || i.Committed >= b.To || b.Thread != 0 && b.Thread != i.ThreadKey {
		return store.ErrCorrupt
	}
	if !validRequiredHoldSource(p.Proposal) || !validRequiredHoldSource(p.Decision) {
		return store.ErrCorrupt
	}
	r := evidence.RequiredRetirement{Seq: p.Proposal.Sequence, Until: postRetention(i.Committed), Identity: i, Envelope: evidence.Event{Kind: "evidence_proposal", RecordID: i.ProposalID, EventSHA: i.ProposalSHA}}
	return validatePostingRetirementValue(r)
}

func validRequiredHoldSource(src RequiredHoldSource) bool {
	day := strconv.FormatUint(uint64(src.Day), 10)
	_, e := time.Parse("20060102", day)
	return src.Sequence > 0 && e == nil && len(day) == 8
}

func (h *RequiredOriginalHolds) replayEntry(entry evidence.Entry) error {
	var p requiredHoldPayload
	if json.Unmarshal(entry.Payload, &p) != nil || p.At < h.floor {
		return store.ErrCorrupt
	}
	if p.Action == "initialize" {
		return h.replayInitialization(p)
	}
	return h.replayChange(p, entry.Event.EventSHA)
}

func (h *RequiredOriginalHolds) replayInitialization(p requiredHoldPayload) error {
	if h.initialized || p.Sequence != 1 {
		return store.ErrCorrupt
	}
	h.initialized, h.floor = true, p.At
	return nil
}

func (h *RequiredOriginalHolds) replayChange(p requiredHoldPayload, sha domain.Hash) error {
	if !h.initialized || p.Binding == nil {
		return store.ErrCorrupt
	}
	old, exists := h.holds[p.Binding.Case]
	if e := requiredHoldTransition(old, exists, p); e != nil {
		return e
	}
	if e := h.checkRequiredRenewalHistory(p); e != nil {
		return e
	}
	if !exists && len(h.holds) >= MaxRequiredHolds {
		return store.ErrCorrupt
	}
	state := "active"
	if p.Action == "release" {
		state = "released"
	}
	h.holds[p.Binding.Case] = RequiredHoldReceipt{Binding: *p.Binding, Sequence: p.Sequence, SHA: sha, At: p.At, State: state, Postings: slices.Clone(p.Postings)}
	if !exists {
		if h.originals == nil {
			h.originals = map[domain.ID]RequiredHoldReceipt{}
		}
		original := h.holds[p.Binding.Case]
		original.Postings = slices.Clone(original.Postings)
		h.originals[p.Binding.Case] = original
	}
	h.rememberRequiredActive(p, old)
	h.floor = p.At
	return nil
}

func requiredHoldTransition(old RequiredHoldReceipt, exists bool, p requiredHoldPayload) error {
	if !exists {
		if p.Action != "reserve" || p.ExpectedSequence != 0 || p.ExpectedSHA != (domain.Hash{}) || p.Binding.Until <= p.At {
			return store.ErrCorrupt
		}
		return nil
	}
	if old.State != "active" || p.ExpectedSequence != old.Sequence || p.ExpectedSHA != old.SHA || !slices.Equal(old.Postings, p.Postings) {
		return store.ErrCorrupt
	}
	if p.Action == "renew" {
		return validateRequiredRenewalChange(old, p)
	}
	if p.Action != "release" || old.Binding != *p.Binding {
		return store.ErrCorrupt
	}
	return nil
}
