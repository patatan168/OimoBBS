// journalを一度開く間だけ、同じ鍵・署名対象の暗号検証結果を共有する。
package evidence

import (
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/domain"
)

const maxReplaySignatures = 4096

type verifiedSignature struct {
	hash      domain.Hash
	signature string
}

// verifyPayloadSignature は各行の元byte/source/hashを再照合した後だけ暗号検証結果を共有する。
// mapはOpen/Inspect内だけで使い、通常追記や別journal・別鍵へ持ち越さない。
func (j *Journal) verifyPayloadSignature(source Source, event Event, payload []byte) ([]byte, error) {
	if err := verifyPayloadIntegrity(source, event, payload, event.PreviousSHA); err != nil {
		return nil, err
	}

	// mapの有無はOpen/Inspectの開始前と全worker終了後にだけ変更する。
	// 通常追記は共有する結果を持たないため、毎回の暗号検証へ直接進む。
	if j.replaySignatures == nil {
		if err := verifyEventSignature(event, j.key.Public().(ed25519.PublicKey)); err != nil {
			return nil, err
		}
		return payload, nil
	}
	stamp := verifiedSignature{event.EventSHA, event.Signature}
	j.replaySignatureMu.Lock()
	_, known := j.replaySignatures[stamp]
	j.replaySignatureMu.Unlock()
	if !known {
		if err := verifyEventSignature(event, j.key.Public().(ed25519.PublicKey)); err != nil {
			return nil, err
		}
		j.replaySignatureMu.Lock()
		if j.replaySignatures != nil && len(j.replaySignatures) < maxReplaySignatures {
			j.replaySignatures[stamp] = struct{}{}
		}
		j.replaySignatureMu.Unlock()
	}
	return payload, nil
}

// verifyReplayPayload は保存seqを含む完全照合を行い、署名確認だけを同じOpen/Inspect内で共有する。
func (j *Journal) verifyReplayPayload(source Source, event Event) ([]byte, error) {
	if err := validateEnvelope(event, event.PreviousSHA, j.keyID, j.key.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	payload, err := decodePayload(event)
	if err != nil {
		return nil, err
	}
	if !matchesPayloadEncoding(payload, event.Payload) {
		return nil, errors.New("invalid payload encoding")
	}
	if err := validSource(payload, source); err != nil {
		return nil, err
	}
	return j.verifyPayloadSignature(source, event, payload)
}
