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

// payloadSource は全JSONの厳密検査とsourceの復号を一度で行う。
func payloadSource(payload []byte) (Source, error) {
	if len(payload) > 512<<10 {
		return Source{}, errors.New("invalid evidence source")
	}
	obj, err := strictjson.SelectFields(payload, "source_owner_id", "source_subkey", "source_control_seq")
	if err != nil {
		return Source{}, err
	}
	var owner domain.ID
	var sub, seq domain.U64
	if err := json.Unmarshal(obj["source_owner_id"], &owner); err != nil {
		return Source{}, err
	}
	if err := json.Unmarshal(obj["source_subkey"], &sub); err != nil {
		return Source{}, err
	}
	if err := json.Unmarshal(obj["source_control_seq"], &seq); err != nil {
		return Source{}, err
	}
	if owner == (domain.ID{}) || seq == 0 {
		return Source{}, errors.New("invalid evidence source")
	}
	return Source{owner, uint64(sub), uint64(seq)}, nil
}

func validSource(payload []byte, source Source) error {
	got, err := payloadSource(payload)
	if err != nil {
		return err
	}
	if got != source {
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
	if err := validateEnvelope(event, previous, keyID, key); err != nil {
		return nil, err
	}
	payload, err := decodePayload(event)
	if err != nil {
		return nil, errors.New("invalid payload encoding")
	}
	return verifyPayload(source, event, payload, previous, keyID, key)
}

// verifyPayload は復号済み本文もenvelopeの元byteへ再照合し、通常Verifyと同じ全検査を行う。
// 公開Verifyと同じ全検査を毎回行い、別の呼出しの検証結果に依存しない。
func verifyPayload(source Source, event Event, payload []byte, previous domain.Hash, keyID uint32, key ed25519.PublicKey) ([]byte, error) {
	if err := validateEnvelope(event, previous, keyID, key); err != nil {
		return nil, err
	}
	if !matchesPayloadEncoding(payload, event.Payload) {
		return nil, errors.New("invalid payload encoding")
	}
	if err := validSource(payload, source); err != nil {
		return nil, err
	}
	return verifyPayloadSignature(source, event, payload, previous, key)
}

// verifyPayloadSignature は元byteとsourceの照合後にhashと署名を検証する。
func verifyPayloadSignature(source Source, event Event, payload []byte, previous domain.Hash, key ed25519.PublicKey) ([]byte, error) {
	if err := verifyPayloadIntegrity(source, event, payload, previous); err != nil {
		return nil, err
	}
	if err := verifyEventSignature(event, key); err != nil {
		return nil, err
	}
	return payload, nil
}

// verifyPayloadIntegrity は署名対象と元byte・所有者・連番の対応を毎回照合する。
func verifyPayloadIntegrity(source Source, event Event, payload []byte, previous domain.Hash) error {
	if sha256.Sum256(payload) != event.PayloadSHA || digest(source, event.RecordID, event.Kind, event.PayloadSHA, previous) != event.EventSHA {
		return errors.New("evidence hash mismatch")
	}
	return nil
}

func verifyEventSignature(event Event, key ed25519.PublicKey) error {
	signature, err := base64.StdEncoding.Strict().DecodeString(event.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != event.Signature || !ed25519.Verify(key, event.EventSHA[:], signature) {
		return errors.New("evidence signature mismatch")
	}
	return nil
}

// validateEnvelope は復号前にも呼び、公開Verifyが巨大なbase64本文を確保するのを防ぐ。
func validateEnvelope(event Event, previous domain.Hash, keyID uint32, key ed25519.PublicKey) error {
	if event.Schema != "evidence-v1" || event.RecordID == (domain.ID{}) || !validKind(event.Kind) || event.SigningKeyID != keyID || keyID == 0 || event.PreviousSHA != previous || len(key) != ed25519.PublicKeySize || len(event.Payload) > 700<<10 {
		return errors.New("invalid evidence envelope")
	}
	return nil
}

// matchesPayloadEncoding は固定長の作業領域で正規base64と元byteを照合する。
// CR/LFを無視するDecodeStringだけでは同値と扱わず、末尾paddingまで一致させる。
func matchesPayloadEncoding(payload []byte, encoded string) bool {
	if base64.StdEncoding.EncodedLen(len(payload)) != len(encoded) {
		return false
	}
	var buffer [1024]byte
	for len(payload) > 0 {
		n := min(len(payload), 768)
		size := base64.StdEncoding.EncodedLen(n)
		base64.StdEncoding.Encode(buffer[:size], payload[:n])
		if string(buffer[:size]) != encoded[:size] {
			return false
		}
		payload, encoded = payload[n:], encoded[size:]
	}
	return true
}
