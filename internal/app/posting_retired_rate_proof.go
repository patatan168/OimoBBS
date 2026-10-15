// 回収済み規制履歴を原本付き履歴と区別し、検証済み所有者/操作/期限へ束縛する。
package app

import (
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

// RetiredRateSchema は元IP・認証情報が回収された受理枠履歴の識別子。内部証明を別途要求する。
const RetiredRateSchema = "required-retired-v1"

// RateRetirementProof は検証済み復旧からだけ作る内部証明。外部から構成できる項目を持たない。
// 元署名や提出証拠ではなく、同じ所有者/キー/履歴の満了を規制復旧へ伝える。
type RateRetirementProof struct {
	owner        domain.ID
	key          uint64
	until, floor domain.Time
	digest       domain.Hash
}

// rateRetirementDigest は返した受理枠の固定項目を束縛し、後からの内容差替えを検出する。
func rateRetirementDigest(v RateRecord) domain.Hash {
	raw, _ := json.Marshal(struct {
		ID     domain.ID
		Number uint32
		At     domain.Time
		Create bool
		Keys   []domain.RateKey
	}{v.ID, v.PostNumber, v.At, v.Create, v.Keys})
	return sha256.Sum256(raw)
}

// ValidateRetiredRateRecord は同じ所有者/キーの検証済み回収履歴と現在時計の一致を確認する。
// Schema文字列だけの偽装、証明の使い回し、本文/IP付き混在と回収前の時計を拒否する。
func ValidateRetiredRateRecord(owner domain.ID, key uint64, v RateRecord, now domain.Time) error {
	p := v.Retirement
	if !rateRetirementScopeMatches(p, owner, key, v) {
		return ErrEvidenceGap
	}
	if v.IP != "" || v.Token != nil || len(v.Overrides) != 0 || v.ID == (domain.ID{}) || v.PostNumber == 0 || rateRetirementDigest(v) != p.digest {
		return ErrEvidenceGap
	}
	if now < p.floor {
		return evidence.ErrRetirementClock
	}
	return nil
}

// rateRetirementScopeMatches は内部証明の所属・元期限・固定Schemaを一緒に照合する。
func rateRetirementScopeMatches(p *RateRetirementProof, owner domain.ID, key uint64, v RateRecord) bool {
	return p != nil && p.owner == owner && p.key == key && p.until == postRetention(v.At) && p.floor >= p.until && v.Schema == RetiredRateSchema && v.TokenStatus == "unavailable"
}
