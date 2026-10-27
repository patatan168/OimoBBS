// 必須原本回収の本文なし対応情報を、照合済みproposal/decisionから構築する。
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// PostingRetirementIdentity はJournalが検証した通常投稿の受理対応を本文なし型へ投影する。
// 未決定・管理操作・対応違いは拒否する。公開WALとの照合と保全予約は所有者が別途行う。
func PostingRetirementIdentity(proposal, decision evidence.Entry) (evidence.RequiredPostingIdentity, error) {
	var p postingProposal
	var d postingDecision
	if proposal.Event.Kind != "evidence_proposal" || decision.Event.Kind != "evidence_decision" || strictjson.Decode(proposal.Payload, &p) != nil || strictjson.Decode(decision.Payload, &d) != nil || !d.matches(p, proposal.Event) {
		return evidence.RequiredPostingIdentity{}, ErrEvidenceGap
	}
	if !retirementEntryMatches(proposal) || !retirementEntryMatches(decision) {
		return evidence.RequiredPostingIdentity{}, ErrEvidenceGap
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
	if e != nil {
		return evidence.RequiredPostingIdentity{}, ErrEvidenceGap
	}
	frame, operation, e := postingFrame(raw)
	if e != nil || sha256.Sum256(raw) != p.FrameSHA || frame.Records[0].ID != p.OperationID || operation.Committed != p.Committed || operation.Revision != p.ThreadSeq {
		return evidence.RequiredPostingIdentity{}, ErrEvidenceGap
	}
	i := evidence.RequiredPostingIdentity{ThreadKey: p.ThreadKey, Type: operation.Type, OperationID: p.OperationID, ThreadSeq: p.ThreadSeq, FrameSHA: p.FrameSHA, Committed: p.Committed, ProposalID: proposal.Event.RecordID, ProposalSHA: proposal.Event.EventSHA, DecisionID: decision.Event.RecordID, DecisionSHA: decision.Event.EventSHA, Outcome: d.Outcome}
	event := proposal.Event
	event.Payload = ""
	if e := validatePostingRetirementValue(evidence.RequiredRetirement{Seq: p.Seq, Envelope: event, Until: p.Retention, Identity: i}); e != nil {
		return evidence.RequiredPostingIdentity{}, e
	}
	return i, nil
}

// retirementEntryMatches は署名検証後に別payloadを渡した取り違えを拒否する。
func retirementEntryMatches(entry evidence.Entry) bool {
	raw, e := base64.StdEncoding.Strict().DecodeString(entry.Event.Payload)
	return e == nil && base64.StdEncoding.EncodeToString(raw) == entry.Event.Payload && bytes.Equal(raw, entry.Payload) && sha256.Sum256(raw) == entry.Event.PayloadSHA
}

func validatePostingRetirement(raw []byte) error {
	var r evidence.RequiredRetirement
	if strictjson.Decode(raw, &r) != nil {
		return store.ErrCorrupt
	}
	return validatePostingRetirementValue(r)
}

// validatePostingRetirementValue は受理6暦月/未受理24時間/接続7日の期限と元ID/hashを検査する。
func validatePostingRetirementValue(r evidence.RequiredRetirement) error {
	i := r.Identity
	if r.Pressure && (i.Outcome != "accepted" || r.Envelope.Kind == rejectedConnectionKind) {
		return store.ErrCorrupt
	}
	if r.Seq == 0 || i.ThreadKey == 0 || i.ThreadSeq == 0 || i.OperationID == (domain.ID{}) || i.FrameSHA == (domain.Hash{}) || i.Committed <= 0 || !postingRetirementDeadlineValid(r) {
		return store.ErrCorrupt
	}
	if i.Type != "create" && i.Type != "append" || (i.Type == "create") != (i.ThreadSeq == 1) {
		return store.ErrCorrupt
	}
	if i.ProposalID == (domain.ID{}) || i.DecisionID == (domain.ID{}) || i.ProposalID == i.DecisionID || i.ProposalSHA == (domain.Hash{}) || i.DecisionSHA == (domain.Hash{}) || i.Outcome != "accepted" && i.Outcome != "not_accepted" || r.Envelope.Payload != "" {
		return store.ErrCorrupt
	}
	switch r.Envelope.Kind {
	case rejectedConnectionKind:
		if i.Outcome != "not_accepted" || r.Envelope.RecordID != rejectedConnectionID(i) {
			return store.ErrCorrupt
		}
	case "evidence_proposal":
		if r.Envelope.RecordID != i.ProposalID || r.Envelope.EventSHA != i.ProposalSHA {
			return store.ErrCorrupt
		}
	case "evidence_decision":
		if r.Envelope.RecordID != i.DecisionID || r.Envelope.EventSHA != i.DecisionSHA {
			return store.ErrCorrupt
		}
	default:
		return store.ErrCorrupt
	}
	return nil
}

func postingRetirementDeadlineValid(r evidence.RequiredRetirement) bool {
	if r.Envelope.Kind == rejectedConnectionKind {
		return r.Until > r.Identity.Committed && r.Until == rejectedConnectionUntil(r.Identity)
	}
	original := postRetention(r.Identity.Committed)
	return r.Until == original || r.Until == evidence.RequiredOriginalDeadline(r.Identity, original)
}
