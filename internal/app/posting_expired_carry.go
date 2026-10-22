// 検証済み満了証跡から短命索引なしの所有者を復旧し、旧時計で再利用しない。
package app

import (
	"crypto/ed25519"
	"oimobbs/internal/domain"
)

// verifyRetirement は署名を持つ全件満了の表現だけを許し、混在した残存行を拒否する。
func (c BodyCarry) verifyRetirement(proof BodyReclamation, now domain.Time, public ed25519.PublicKey) error {
	if c.Retirement == nil || len(c.Dedups) != 0 || len(c.Rates) != 0 {
		return ErrEvidenceGap
	}
	return c.Retirement.Verify(proof, now, public)
}

// RestoreBodyCarry は通常の集合か、信頼した鍵で検証した全件満了証跡を接続する。
// 満了の場合は再送拒否/受理枠を復元せず、回収時計を所有者の下限へ引き継ぐ。
// 元証拠・ファイルは回収せず、製品正本への登録と物理回収は呼出元が別に行う。
func (p *PostingLog) RestoreBodyCarry(carry BodyCarry, now domain.Time, public ed25519.PublicKey) error {
	if carry.Retirement == nil {
		return p.UseBodyCarry(carry)
	}
	if p.reclaimed == nil || p.reclaimed.proof.Owner != p.owner || uint64(p.reclaimed.proof.Key) != p.key {
		return ErrEvidenceGap
	}
	if e := carry.verifyRetirement(p.reclaimed.proof, now, public); e != nil {
		return e
	}
	owned := *carry.Retirement
	for i := range p.reclaimed.records {
		p.reclaimed.records[i].Dedup = nil
	}
	p.reclaimed.carry = &BodyCarry{Dedups: []DedupCarry{}, Rates: []RateCarry{}, Retirement: &owned}
	p.retiredFloor = max(p.retiredFloor, owned.At)
	return nil
}

// hasExpiredBodyCarry は接続時に検証して複製した満了証跡の有無を返す。
func (p *PostingLog) hasExpiredBodyCarry() bool {
	return p.reclaimed != nil && p.reclaimed.carry != nil && p.reclaimed.carry.Retirement != nil
}

// checkExpiredBoardCarries はどのキーの修復よりも先に、全満了証跡の所有者と時計を検査する。
func checkExpiredBoardCarries(owner domain.ID, proofs map[uint64]BodyReclamation, carries map[uint64]BodyCarry, now domain.Time, public ed25519.PublicKey) error {
	for key, carry := range carries {
		if carry.Retirement == nil {
			continue
		}
		proof, ok := proofs[key]
		if !ok || proof.Owner != owner || uint64(proof.Key) != key {
			return ErrEvidenceGap
		}
		if e := carry.verifyRetirement(proof, now, public); e != nil {
			return e
		}
	}
	return nil
}
