// 期限内に署名された案件intentを、固定必須原本の元lease更新へ束縛する。
package app

import (
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// RequiredHoldApproval は旧期限内の承認時刻と案件intent版。本人情報/本文は持たない。
type RequiredHoldApproval struct {
	Revision domain.U64  `json:"case_revision"`
	At       domain.Time `json:"approved_at_ns"`
}

// RequiredHoldRenewalReceipt は元履歴で検証した旧参照・承認・解除直前までの新参照。
type RequiredHoldRenewalReceipt struct {
	Original RequiredHoldReceipt
	Approval RequiredHoldApproval
	Current  RequiredHoldReceipt
}

// RenewalReceipt は最後の延長CAS/承認を独立metadataとして返す。原本取得や認可は別に行う。
func (h *RequiredOriginalHolds) RenewalReceipt(id domain.ID) (RequiredHoldRenewalReceipt, bool, error) {
	if h.stopped {
		return RequiredHoldRenewalReceipt{}, false, store.ErrIncomplete
	}
	r, found := h.renewals[id]
	if !found {
		return RequiredHoldRenewalReceipt{}, false, nil
	}
	active, exists, e := h.LastActiveReceipt(id)
	if e != nil || !exists {
		return RequiredHoldRenewalReceipt{}, false, store.ErrCorrupt
	}
	r.Original.Postings = slices.Clone(r.Original.Postings)
	return RequiredHoldRenewalReceipt{r.Original, r.Approval, active}, true, nil
}

type requiredHoldRenewal struct {
	Original RequiredHoldReceipt
	Approval RequiredHoldApproval
	Until    domain.Time
}

// Renew は先行署名済み承認で固定原本を再検証して元leaseをCAS更新する。
// 呼出元は承認/現在認可/reader47/容量と所有排他を検査する。回収済み原本は復活させない。
func (h *RequiredOriginalHolds) Renew(original RequiredHoldReceipt, approval RequiredHoldApproval, until domain.Time, journals map[uint64]*evidence.Journal, now domain.Time) (RequiredHoldReceipt, error) {
	if e := h.checkClock(now); e != nil {
		return RequiredHoldReceipt{}, e
	}
	if !validRequiredApproval(original, approval, until, now) {
		return RequiredHoldReceipt{}, store.ErrCorrupt
	}
	current, replay, e := h.requiredRenewalCurrent(original, approval, until)
	if e != nil {
		return current, e
	}
	if e = h.verifyRequiredRenewalOriginals(current, journals); e != nil {
		return current, e
	}
	if replay {
		return current, nil
	}
	b := current.Binding
	b.Until = until
	p := requiredHoldPayload{Action: "renew", At: now, Binding: &b, ExpectedSequence: current.Sequence, ExpectedSHA: current.SHA, Postings: slices.Clone(current.Postings), Approval: &approval}
	if e = h.append(p); e != nil {
		return RequiredHoldReceipt{}, e
	}
	result, _, e := h.Receipt(b.Case)
	return result, e
}

// requiredRenewalCurrent は正本全一致または同じ承認の直後再送だけを許す。
func (h *RequiredOriginalHolds) requiredRenewalCurrent(original RequiredHoldReceipt, a RequiredHoldApproval, until domain.Time) (RequiredHoldReceipt, bool, error) {
	current, exists := h.holds[original.Binding.Case]
	if !exists || current.State != "active" {
		return current, false, store.ErrIncomplete
	}
	previous, renewed := h.renewals[original.Binding.Case]
	if sameRequiredHoldReceipt(current, original) {
		if renewed && (a.Revision <= previous.Approval.Revision || a.At < previous.Approval.At) {
			return current, false, store.ErrCorrupt
		}
		return current, false, nil
	}
	if !renewed || !sameRequiredHoldReceipt(previous.Original, original) || previous.Approval != a || previous.Until != until {
		return current, false, store.ErrCorrupt
	}
	current.Postings = slices.Clone(current.Postings)
	return current, true, nil
}

// validRequiredApproval は旧期限内承認と承認起算180日・単調版/期限を検査する。
func validRequiredApproval(original RequiredHoldReceipt, a RequiredHoldApproval, until, now domain.Time) bool {
	if original.State != "active" || ValidateRequiredHoldReceipt(original) != nil || a.Revision <= original.Binding.Revision {
		return false
	}
	if a.At < original.At || a.At >= original.Binding.Until || a.At > now {
		return false
	}
	if a.At > domain.Time(math.MaxInt64-int64(180*24*time.Hour)) {
		return false
	}
	return until > original.Binding.Until && until > now && until <= a.At+domain.Time(180*24*time.Hour)
}

// verifyRequiredRenewalOriginals は元期限後の再開でも両側の実原本/署名/対応を全部照合する。
func (h *RequiredOriginalHolds) verifyRequiredRenewalOriginals(current RequiredHoldReceipt, journals map[uint64]*evidence.Journal) error {
	for _, p := range current.Postings {
		if _, e := h.fetchPosting(p, journals); e != nil {
			return e
		}
	}
	return nil
}

// validRequiredHoldSchema は現行v2の全操作を検査し、延長にだけ承認欄を要求する。
func validRequiredHoldSchema(p requiredHoldPayload) bool {
	if p.Action == "renew" {
		return p.Schema == "required-original-hold-v2" && p.Approval != nil
	}
	return p.Schema == "required-original-hold-v2" && p.Approval == nil
}

// validateRequiredRenewalChange は署名履歴の元CASと固定範囲/初回版を維持し、承認だけで期限を更新する。
func validateRequiredRenewalChange(old RequiredHoldReceipt, p requiredHoldPayload) error {
	if p.Approval == nil || !validRequiredApproval(old, *p.Approval, p.Binding.Until, p.At) {
		return store.ErrCorrupt
	}
	b := old.Binding
	b.Until = p.Binding.Until
	if b != *p.Binding {
		return store.ErrCorrupt
	}
	return nil
}

// rememberRequiredActive は延長承認の再送根拠と解除直前のactive参照を復元する。
func (h *RequiredOriginalHolds) rememberRequiredActive(p requiredHoldPayload, old RequiredHoldReceipt) {
	if p.Action == "release" {
		return
	}
	if h.activeReceipts == nil {
		h.activeReceipts = map[domain.ID]RequiredHoldReceipt{}
	}
	current := h.holds[p.Binding.Case]
	current.Postings = slices.Clone(current.Postings)
	h.activeReceipts[p.Binding.Case] = current
	if p.Action != "renew" {
		return
	}
	if h.renewals == nil {
		h.renewals = map[domain.ID]requiredHoldRenewal{}
	}
	old.Postings = slices.Clone(old.Postings)
	h.renewals[p.Binding.Case] = requiredHoldRenewal{old, *p.Approval, p.Binding.Until}
	h.minimumReader = 47
}

// checkRequiredRenewalHistory は複数延長でも承認版/時刻の逆行を元署名履歴から拒否する。
func (h *RequiredOriginalHolds) checkRequiredRenewalHistory(p requiredHoldPayload) error {
	if p.Action != "renew" {
		return nil
	}
	previous, exists := h.renewals[p.Binding.Case]
	if exists && (p.Approval.Revision <= previous.Approval.Revision || p.Approval.At < previous.Approval.At) {
		return store.ErrCorrupt
	}
	return nil
}
