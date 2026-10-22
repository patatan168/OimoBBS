// 短命carryの満了を元の署名済み集合へ束縛し、時計逆行時の再利用を拒否する。
package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

var ErrBodyCarryNotExpired = errors.New("body carry has not expired")

// BodyCarryRetirement は全件満了の証跡。元の本文・HMAC・受理枠を含めない。
// 保存と物理回収の実行権限は、この値だけでは与えない。
type BodyCarryRetirement struct {
	Schema       uint32      `json:"schema"`
	Proof        domain.Hash `json:"body_reclamation_sha256"`
	At           domain.Time `json:"retired_at_ns"`
	LatestExpiry domain.Time `json:"latest_expiry_ns"`
	Dedups       uint32      `json:"dedup_count"`
	Rates        uint32      `json:"rate_count"`
	Signature    string      `json:"signature"`
}

// PrepareBodyCarryRetirement は元の全carryを照合し、全件満了後だけ既存鍵で署名する。
// 状態やファイルは変更せず、呼出元が所有排他・署名先行保存・回収再開を担当する。
func PrepareBodyCarryRetirement(proof BodyReclamation, carry BodyCarry, now domain.Time, key ed25519.PrivateKey) (BodyCarryRetirement, error) {
	var out BodyCarryRetirement
	if len(key) != ed25519.PrivateKeySize || proof.Verify(key.Public().(ed25519.PublicKey)) != nil {
		return out, store.ErrCorrupt
	}
	latest, e := retirementCarryExpiry(proof, carry)
	if e != nil {
		return out, e
	}
	if now < max(proof.At, proof.Floor) {
		return out, evidence.ErrRetirementClock
	}
	if now < latest {
		return out, ErrBodyCarryNotExpired
	}
	bytes, e := json.Marshal(proof)
	if e != nil {
		return out, e
	}
	out = BodyCarryRetirement{Schema: 1, Proof: sha256.Sum256(bytes), At: now, LatestExpiry: latest, Dedups: uint32(len(carry.Dedups)), Rates: uint32(len(carry.Rates))}
	raw, e := json.Marshal(out)
	if e != nil {
		return BodyCarryRetirement{}, e
	}
	out.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("oimo/body-carry-retirement/v1\x00"), raw...)))
	return out, nil
}

// retirementCarryExpiry は元の署名digestと全carryを照合してから期限を調べる。
func retirementCarryExpiry(proof BodyReclamation, carry BodyCarry) (domain.Time, error) {
	if carry.Retirement != nil {
		return 0, ErrEvidenceGap
	}
	d, r, e := carry.Digest(proof.Floor)
	if e != nil || d != proof.DedupSHA || r != proof.RateSHA {
		return 0, ErrEvidenceGap
	}
	return carry.latestExpiry(proof.Floor)
}

// latestExpiry は固定CRC・元の期限を検査し、再送拒否と受理枠の最も遅い満了を返す。
func (v BodyCarry) latestExpiry(floor domain.Time) (domain.Time, error) {
	var latest domain.Time
	for _, c := range v.Dedups {
		d, e := c.Validate(floor)
		if e != nil {
			return 0, e
		}
		latest = max(latest, d.Value.Expires)
	}
	for _, c := range v.Rates {
		if e := c.Validate(); e != nil {
			return 0, e
		}
		latest = max(latest, c.Expires)
	}
	return latest, nil
}

// Verify は元の回収正本・署名・固定時刻を照合し、回収時刻より前の時計を拒否する。
// 最新正本への登録や物理消去の完了は、呼出元が別に検査する。
func (v BodyCarryRetirement) Verify(proof BodyReclamation, now domain.Time, key ed25519.PublicKey) error {
	if proof.Verify(key) != nil || v.shape(proof) != nil {
		return store.ErrCorrupt
	}
	proofBytes, e := json.Marshal(proof)
	if e != nil || v.Proof != sha256.Sum256(proofBytes) {
		return store.ErrCorrupt
	}
	signature, _ := base64.RawStdEncoding.DecodeString(v.Signature)
	v.Signature = ""
	raw, e := json.Marshal(v)
	if e != nil || !ed25519.Verify(key, append([]byte("oimo/body-carry-retirement/v1\x00"), raw...), signature) {
		return store.ErrCorrupt
	}
	if now < v.At {
		return evidence.ErrRetirementClock
	}
	return nil
}

// shape は署名のcanonical表現と、既存索引の件数・時計境界を検査する。
func (v BodyCarryRetirement) shape(proof BodyReclamation) error {
	if v.Schema != 1 || v.Proof == (domain.Hash{}) || v.At < max(proof.At, proof.Floor) || v.LatestExpiry < 0 || v.LatestExpiry > v.At || v.Dedups > store.MaxPackEntries || v.Rates > store.MaxPackEntries {
		return store.ErrCorrupt
	}
	_, e := v.signatureBytes()
	return e
}

// ValidateFormat は保存codec向けの型・境界検査。信頼鍵の検証はVerifyで別に行う。
func (v BodyCarryRetirement) ValidateFormat(proof BodyReclamation) error {
	return v.shape(proof)
}

// VerifySource は消去前の全集合も照合し、証跡の件数と最終満了が元値から導かれることを確認する。
func (v BodyCarryRetirement) VerifySource(proof BodyReclamation, carry BodyCarry, now domain.Time, key ed25519.PublicKey) error {
	if e := v.Verify(proof, now, key); e != nil {
		return e
	}
	latest, e := retirementCarryExpiry(proof, carry)
	if e != nil || latest != v.LatestExpiry || len(carry.Dedups) != int(v.Dedups) || len(carry.Rates) != int(v.Rates) {
		return ErrEvidenceGap
	}
	return nil
}

// signatureBytes は既存の署名規約と同じcanonical Base64だけを受け付ける。
func (v BodyCarryRetirement) signatureBytes() ([]byte, error) {
	raw, e := base64.RawStdEncoding.Strict().DecodeString(v.Signature)
	if e != nil || len(raw) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(raw) != v.Signature {
		return nil, store.ErrCorrupt
	}
	return raw, nil
}
