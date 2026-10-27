// 容量回収候補の最終投稿と満杯状態を、本文や接続情報を返さず所有列内で調べる。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// StoragePressureState は最終ユーザー投稿・満杯と回収残りを返す。
// システム報告・固定スレッド・停止列・本文回収済みで原本も回収済みの列は対象外。
func (p *PostingLog) StoragePressureState() (last domain.Time, full, pending, ok bool) {
	if p.stopped || p.key == 1 {
		return
	}
	var after domain.After
	var policy domain.Policy
	if p.thread != nil {
		s := p.thread.State()
		after, policy = s.After, s.Policy
	} else if p.reclaimed != nil {
		if p.reclaimed.proof.Kind != "pressure" {
			return
		}
		after, policy = p.reclaimed.proof.After, p.reclaimed.proof.Policy
	} else {
		return
	}
	if policy.Pinned {
		return
	}
	pending = p.thread != nil
	if !pending {
		for _, r := range p.records() {
			if (r.Type == "create" || r.Type == "append") && !p.originalPairRetired(r.ID) {
				pending = true
				break
			}
		}
	}
	full = after.UserCount >= policy.UserPostLimit || uint64(after.DATBytes) >= uint64(policy.DATUserLimit) || after.EndReason != nil && (*after.EndReason == "count" || *after.EndReason == "bytes")
	return after.LastUserAt, full, pending, after.LastUserAt > 0
}

// StoragePressureHeld は公開停止前に全受理操作の両原本の保全を検査する。
// 呼出元は案件/元予約の共通排他を検査開始から回収完了まで保持する。
func (p *PostingLog) StoragePressureHeld(journals []*evidence.Journal, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (bool, error) {
	selected := map[domain.ID]bool{}
	for _, r := range p.records() {
		if r.Type == "create" || r.Type == "append" {
			selected[r.ID] = true
		}
	}
	identities, e := p.requiredScanDecisions(journals, selected)
	if e != nil {
		return false, e
	}
	for id := range selected {
		i, ok := identities[id]
		if !ok {
			return false, ErrEvidenceGap
		}
		protected, e := held(i, now)
		if e != nil || protected {
			return protected, e
		}
	}
	return false, nil
}
