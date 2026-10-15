// Package evidence は非公開接続記録の署名と元byte検証を担当する。
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"slices"
	"strconv"
)

// Event は設計22の署名済みvalue。payloadの元byteを保持する。
type Event struct {
	Schema       string      `json:"schema"`
	RecordID     domain.ID   `json:"record_id"`
	Kind         string      `json:"kind"`
	Payload      string      `json:"payload_base64"`
	PayloadSHA   domain.Hash `json:"payload_sha256"`
	PreviousSHA  domain.Hash `json:"previous_event_sha256"`
	EventSHA     domain.Hash `json:"event_sha256"`
	SigningKeyID uint32      `json:"signing_key_id"`
	Signature    string      `json:"signature_base64"`
}
type Source struct {
	Owner       domain.ID
	Subkey, Seq uint64
}

func digest(source Source, id domain.ID, kind string, payload, previous domain.Hash) domain.Hash {
	h := sha256.New()
	for _, v := range [][]byte{[]byte("oimo/evidence/v1"), source.Owner[:], []byte(strconv.FormatUint(source.Subkey, 10)), []byte(strconv.FormatUint(source.Seq, 10)), id[:], []byte(kind), payload[:], previous[:]} {
		writeLP(h, v)
	}
	var result domain.Hash
	copy(result[:], h.Sum(nil))
	return result
}
func writeLP(h hash.Hash, v []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(v)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(v)
}
func validSource(payload []byte, source Source) error {
	if len(payload) > 512<<10 || source.Owner == (domain.ID{}) || source.Seq == 0 {
		return errors.New("invalid evidence source")
	}
	if e := strictjson.Validate(payload); e != nil {
		return e
	}
	var obj map[string]json.RawMessage
	if e := json.Unmarshal(payload, &obj); e != nil {
		return e
	}
	var owner domain.ID
	var sub, seq domain.U64
	if e := json.Unmarshal(obj["source_owner_id"], &owner); e != nil {
		return e
	}
	if e := json.Unmarshal(obj["source_subkey"], &sub); e != nil {
		return e
	}
	if e := json.Unmarshal(obj["source_control_seq"], &seq); e != nil {
		return e
	}
	if owner != source.Owner || uint64(sub) != source.Subkey || uint64(seq) != source.Seq {
		return errors.New("evidence source mismatch")
	}
	return nil
}
func validKind(kind string) bool {
	return slices.Contains([]string{"rejected_connection", "evidence_proposal", "evidence_decision", "thread_admin_proposal", "thread_admin_decision", "attempt", "response", "receipt", "tombstone", "checkpoint", "journal_checkpoint"}, kind)
}

// Seal は業務層でスキーマ検証済みのpayloadを署名する。本文の秘密除去は呼出前に必要。
func Seal(source Source, id domain.ID, kind string, payload []byte, previous domain.Hash, keyID uint32, key ed25519.PrivateKey) (Event, error) {
	var e Event
	if err := validSource(payload, source); err != nil {
		return e, err
	}
	if id == (domain.ID{}) || !validKind(kind) || keyID == 0 || len(key) != ed25519.PrivateKeySize {
		return e, errors.New("invalid evidence signing parameters")
	}
	e = Event{Schema: "evidence-v1", RecordID: id, Kind: kind, Payload: base64.StdEncoding.EncodeToString(payload), PayloadSHA: sha256.Sum256(payload), PreviousSHA: previous, SigningKeyID: keyID}
	e.EventSHA = digest(source, id, kind, e.PayloadSHA, previous)
	e.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, e.EventSHA[:]))
	return e, nil
}

// Verify は鍵・元byte・source・直前hashを照合し、業務検証前のpayloadを返す。
func Verify(source Source, event Event, previous domain.Hash, keyID uint32, key ed25519.PublicKey) ([]byte, error) {
	if event.Schema != "evidence-v1" || event.RecordID == (domain.ID{}) || !validKind(event.Kind) || event.SigningKeyID != keyID || keyID == 0 || event.PreviousSHA != previous || len(key) != ed25519.PublicKeySize || len(event.Payload) > 700<<10 {
		return nil, errors.New("invalid evidence envelope")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(event.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != event.Payload {
		return nil, errors.New("invalid payload encoding")
	}
	if err = validSource(payload, source); err != nil {
		return nil, err
	}
	if sha256.Sum256(payload) != event.PayloadSHA || digest(source, event.RecordID, event.Kind, event.PayloadSHA, previous) != event.EventSHA {
		return nil, errors.New("evidence hash mismatch")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(event.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != event.Signature || !ed25519.Verify(key, event.EventSHA[:], signature) {
		return nil, errors.New("evidence signature mismatch")
	}
	return payload, nil
}
