// 投稿所有者は署名済み元payloadを共有し、frame・captureの重複保持を照会時に復元する。
package app

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/evidence"
	"reflect"
)

// retainProposalEntry は通常投稿の本文表現だけを解放し、採番・受理判定のmetadataを残す。
// 永続化と署名byteは変更しない。管理操作と回収済みの本文なし対応は従来の表現を保つ。
func retainProposalEntry(payload postingProposal, event evidence.Event) proposalEntry {
	entry := proposalEntry{payload: payload, event: event}
	if event.Kind == "evidence_proposal" && event.Payload != "" && payload.Frame != "" {
		entry.payload.Frame = ""
		entry.payload.Capture = nil
		entry.compact = true
	}
	return entry
}

// originalPayload は検証済み署名byteから独立した本文を復元する。結果を所有者のcacheへ残さない。
// 原本回収済みの場合は本文を補完せず、残存するmetadataを返す。
func (entry proposalEntry) originalPayload() (postingProposal, error) {
	if !entry.compact {
		return entry.payload, nil
	}
	if entry.payload.Frame != "" || entry.payload.Capture != nil || entry.event.Payload == "" {
		return postingProposal{}, ErrEvidenceGap
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(entry.event.Payload)
	if err != nil || sha256.Sum256(raw) != entry.event.PayloadSHA || base64.StdEncoding.EncodeToString(raw) != entry.event.Payload {
		return postingProposal{}, ErrEvidenceGap
	}
	var payload postingProposal
	// 保存前とreplay時に完全スキーマを検査済み。ここでは元byteと保持metadataを再照合する。
	if json.Unmarshal(raw, &payload) != nil {
		return postingProposal{}, ErrEvidenceGap
	}
	metadata := payload
	metadata.Frame = ""
	metadata.Capture = nil
	if !reflect.DeepEqual(metadata, entry.payload) {
		return postingProposal{}, ErrEvidenceGap
	}
	return payload, nil
}

// decodeFrame は回収済み本文を補完せず、元の標準base64 frameだけを返す。
func (entry proposalEntry) decodeFrame() ([]byte, error) {
	payload, err := entry.originalPayload()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.Strict().DecodeString(payload.Frame)
}

func (entry proposalEntry) originalCapture() ([]byte, error) {
	payload, err := entry.originalPayload()
	return payload.Capture, err
}
