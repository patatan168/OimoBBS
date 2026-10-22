// 原本回収後も、保全copyの両側元署名・位置・実frame対応を固定予約へ照合する。
package app

import (
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ValidateRequiredHeldCopy はcopyの全対応/署名/元位置を検査する。現在原本の存在や開示認可は要求しない。
// expectedは元台帳/案件の署名照合済み参照を使い、成功を現在元の予約有効性として使わない。
func ValidateRequiredHeldCopy(board domain.ID, expected RequiredHeldPosting, record AcceptedEvidence, keyID uint32, public ed25519.PublicKey) error {
	if board == (domain.ID{}) || record.Board != board || keyID == 0 || len(public) != ed25519.PublicKeySize {
		return store.ErrCorrupt
	}
	verifier := &RequiredOriginalHolds{board: board, keyID: keyID, public: public}
	actual, e := verifier.copiedPosting(record)
	if e != nil {
		return e
	}
	if actual != expected {
		return ErrEvidenceGap
	}
	return nil
}

func (h *RequiredOriginalHolds) copiedPosting(record AcceptedEvidence) (RequiredHeldPosting, error) {
	var result RequiredHeldPosting
	var e error
	result.Proposal, e = h.sourceOf(record.Proposal)
	if e != nil {
		return result, e
	}
	result.Decision, e = h.sourceOf(record.Decision)
	if e != nil {
		return result, e
	}
	result.Identity, e = PostingRetirementIdentity(record.Proposal, record.Decision)
	if e != nil {
		return result, e
	}
	if !requiredRecordMatches(record, result.Identity) {
		return result, ErrEvidenceGap
	}
	actual, e := requiredAcceptedPair(h.board, result.Identity, record.Proposal, record.Decision)
	if e != nil || actual.Post != record.Post {
		return result, ErrEvidenceGap
	}
	return result, nil
}
