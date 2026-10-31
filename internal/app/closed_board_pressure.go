// 先に本文回収されたスレッドにも、閉鎖板の原本早期回収を署名付きで許可する。
package app

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ClosedBoardPressure は元の本文回収証明を変更せず、閉鎖板の容量回収日時を束縛する。
type ClosedBoardPressure struct {
	Proof     domain.Hash `json:"body_proof_sha256"`
	ClosedAt  domain.Time `json:"closed_at_ns"`
	At        domain.Time `json:"created_at_ns"`
	Signature string      `json:"signature"`
}

// SignClosedBoardPressure は検証済み本文回収証明に対する早期回収許可を署名する。
func SignClosedBoardPressure(proof BodyReclamation, closedAt, at domain.Time, key ed25519.PrivateKey) (ClosedBoardPressure, error) {
	if len(key) != ed25519.PrivateKeySize || proof.Verify(key.Public().(ed25519.PublicKey)) != nil {
		return ClosedBoardPressure{}, store.ErrCorrupt
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return ClosedBoardPressure{}, err
	}
	v := ClosedBoardPressure{Proof: sha256.Sum256(raw), ClosedAt: closedAt, At: at}
	raw, err = json.Marshal(v)
	if err != nil {
		return v, err
	}
	v.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("oimo/closed-board-pressure/v1\x00"), raw...)))
	return v, v.Verify(proof, key.Public().(ed25519.PublicKey))
}

// Verify は別のスレッド・別の本文回収証明への許可の流用と、閉鎖前の回収を拒否する。
func (v ClosedBoardPressure) Verify(proof BodyReclamation, public ed25519.PublicKey) error {
	raw, err := json.Marshal(proof)
	if err != nil || v.Proof != sha256.Sum256(raw) || v.ClosedAt <= 0 || v.At < max(v.ClosedAt, proof.At) || len(public) != ed25519.PublicKeySize {
		return store.ErrCorrupt
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(v.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawStdEncoding.EncodeToString(signature) != v.Signature {
		return store.ErrCorrupt
	}
	v.Signature = ""
	raw, err = json.Marshal(v)
	if err != nil || !ed25519.Verify(public, append([]byte("oimo/closed-board-pressure/v1\x00"), raw...), signature) {
		return store.ErrCorrupt
	}
	return nil
}

// UseClosedBoardPressure は先行保存された署名済み許可だけを稼働中の回収所有者へ適用する。
func (p *PostingLog) UseClosedBoardPressure(v ClosedBoardPressure, now domain.Time, public ed25519.PublicKey) error {
	if p.reclaimed == nil || now < v.At || v.Verify(p.reclaimed.proof, public) != nil {
		return ErrEvidenceGap
	}
	p.reclaimed.proof.ClosedPressure = &v
	return nil
}

// pressureTime は署名検証後の本文回収証明だけで使用する。
func (v BodyReclamation) pressureTime() domain.Time {
	if v.Kind == "pressure" || v.Kind == "closure" {
		return v.At
	}
	if v.ClosedPressure != nil {
		return v.ClosedPressure.At
	}
	return 0
}
