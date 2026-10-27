// 公開本文の物理回収と独立carryを必須原本回収へ束縛し、稼働中も本文なしへ切り替える。
package app

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
)

// CheckRequiredOriginalReclamation は原本回収前に公開本文の物理消去と独立carryを検査する。
// 板所有排他内で呼び、完了taskと案件/元予約の保護は呼出元が別途照合する。
// proof作成だけ・carry未保存・時計逆行では回収を許可しない。状態やfileは変更しない。
func (p *PostingLog) CheckRequiredOriginalReclamation(ctx context.Context, now domain.Time, public ed25519.PublicKey) error {
	if p.stopped || p.thread != nil || p.reclaimed == nil || p.reclaimed.carry == nil {
		return ErrEvidenceGap
	}
	proof := p.reclaimed.proof
	if e := proof.Verify(public); e != nil {
		return e
	}
	if !p.originalReclamationMatchesOwner() {
		return ErrEvidenceGap
	}
	if now < max(proof.At, proof.Floor, p.retiredFloor) {
		return evidence.ErrRetirementClock
	}
	if e := checkOriginalReclamationCarry(p.reclaimed, now, public); e != nil {
		return e
	}
	return store.CheckBodyReclamationComplete(ctx, filepath.Join(p.parent, fmt.Sprint(p.key)), proof.Files)
}

func (p *PostingLog) originalReclamationMatchesOwner() bool {
	proof := p.reclaimed.proof
	return proof.Owner == p.owner && uint64(proof.Key) == p.key && bodyRecordsSHA(p.reclaimed.records) == proof.RecordsSHA
}

// checkOriginalReclamationCarry は署名digestと全受理操作の枠履歴を両方確認する。
func checkOriginalReclamationCarry(r *reclaimedBody, now domain.Time, public ed25519.PublicKey) error {
	if r.carry.Retirement != nil {
		return r.carry.verifyRetirement(r.proof, now, public)
	}
	d, rates, e := r.carry.Digest(r.proof.Floor)
	if e != nil || d != r.proof.DedupSHA || rates != r.proof.RateSHA {
		return ErrEvidenceGap
	}
	return checkRetiredCarryCompleteness(r.records, r.proof, r.carry)
}

// ReloadRetiredOriginals は原本回収後、同じ所有者を検証済み本文なし状態へ置き換える。
// 全期間のJournalを渡し、原本回収と同じ板排他内で実行する。
// raw frame/captureを持つ旧mapを解放し、回収署名/独立carryから枠履歴を復旧する。
// 回収後の再構築に失敗した所有者は停止し、通常処理へ戻さない。
func (p *PostingLog) ReloadRetiredOriginals(ctx context.Context, journals []*evidence.Journal, now domain.Time, public ed25519.PublicKey) error {
	if e := p.CheckRequiredOriginalReclamation(ctx, now, public); e != nil {
		p.stopWriter()
		return e
	}
	next, e := OpenPostingWithRetiredOriginals(p.parent, p.owner, p.key, journals, p.active, now, p.reclaimed.proof, p.reclaimed.carry, public)
	if e != nil {
		p.stopWriter()
		return e
	}
	*p = *next
	return nil
}
