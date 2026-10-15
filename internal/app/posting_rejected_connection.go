// 未受理の本文原本から接続観測と結果だけを7日記録へ移し、同じ署名列で回収する。
package app

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"time"
)

const rejectedConnectionKind = "rejected_connection"

type rejectedConnection struct {
	Owner       domain.ID                        `json:"source_owner_id"`
	Day         domain.U64                       `json:"source_subkey"`
	Seq         domain.U64                       `json:"source_control_seq"`
	ThreadKey   domain.U64                       `json:"thread_key"`
	OperationID domain.ID                        `json:"operation_id"`
	Until       domain.Time                      `json:"retention_until_ns"`
	Identity    evidence.RequiredPostingIdentity `json:"posting_identity"`
	Observation *evidence.HTTPObservation        `json:"connection"`
	Missing     string                           `json:"connection_missing_reason"`
	Decided     domain.Time                      `json:"decision_at_ns"`
	Recovered   bool                             `json:"recovered"`
}

func rejectedConnectionID(i evidence.RequiredPostingIdentity) domain.ID {
	raw := append([]byte("rejected_connection_v1"), i.ProposalID[:]...)
	raw = append(raw, i.DecisionID[:]...)
	hash := sha256.Sum256(raw)
	var id domain.ID
	copy(id[:], hash[:16])
	return id
}

func rejectedConnectionUntil(i evidence.RequiredPostingIdentity) domain.Time {
	return i.Committed + domain.Time(7*24*time.Hour)
}

// validateRejectedConnection は本文/資格を許さず、接続欠測も明示する完全型を検査する。
func validateRejectedConnection(raw []byte) error {
	var v rejectedConnection
	if strictjson.Decode(raw, &v) != nil {
		return store.ErrCorrupt
	}
	if !rejectedConnectionSourceValid(v) || v.Decided < v.Identity.Committed {
		return store.ErrCorrupt
	}
	if e := validatePostingRetirementValue(evidence.RequiredRetirement{Seq: v.Seq, Envelope: evidence.Event{Kind: rejectedConnectionKind, RecordID: rejectedConnectionID(v.Identity)}, Until: v.Until, Identity: v.Identity}); e != nil {
		return store.ErrCorrupt
	}
	if v.Observation == nil {
		if v.Missing != "not_collected" {
			return store.ErrCorrupt
		}
		return nil
	}
	return validateRejectedObservation(v)
}

func validateRejectedObservation(v rejectedConnection) error {
	if v.Missing != "" || v.Observation.BoardID != v.Owner {
		return store.ErrCorrupt
	}
	raw, e := json.Marshal(v.Observation)
	if e != nil {
		return e
	}
	return evidence.ValidateHTTPObservation(raw)
}

// preserveRejectedConnections は本文回収前に7日期限の接続/結果をSyncし、再送は固定IDで照合する。
func (p *PostingLog) preserveRejectedConnections(journals []*evidence.Journal, candidates []evidence.RequiredPostingIdentity, now domain.Time) error {
	for _, i := range candidates {
		if i.Outcome != "not_accepted" || rejectedConnectionUntil(i) <= now {
			continue
		}
		if e := p.preserveRejectedConnection(journals, i); e != nil {
			return e
		}
	}
	return nil
}

func (p *PostingLog) preserveRejectedConnection(journals []*evidence.Journal, i evidence.RequiredPostingIdentity) error {
	id := rejectedConnectionID(i)
	existing, found, e := findOriginalCandidate(journals, id)
	if e != nil {
		return e
	}
	if found {
		var v rejectedConnection
		if !rejectedConnectionReplayMatches(existing, i, &v) {
			return ErrEvidenceGap
		}
		return nil
	}
	proposal, ok := p.proposals[i.OperationID]
	if !ok || len(proposal.payload.Capture) == 0 {
		return ErrEvidenceGap
	}
	v, e := buildRejectedConnection(i, proposal.payload.Capture)
	if e != nil {
		return e
	}
	if e = fillRejectedDecision(&v, journals); e != nil {
		return e
	}
	_, result := p.active.Append(id, rejectedConnectionKind, i.Committed, func(source evidence.Source) ([]byte, error) {
		v.Owner, v.Day, v.Seq = source.Owner, domain.U64(source.Subkey), domain.U64(source.Seq)
		return json.Marshal(v)
	})
	if result.Status != store.Durable {
		p.stopWriter()
		return result.Err
	}
	return nil
}

// checkRejectedConnections は保存済み接続記録を未受理対応へ再照合する。
func (p *PostingLog) checkRejectedConnections(entries []evidence.Entry, decisions map[domain.ID]postingDecision) error {
	seen := map[domain.ID]bool{}
	for _, entry := range entries {
		if entry.Event.Kind != rejectedConnectionKind {
			continue
		}
		var v rejectedConnection
		if strictjson.Decode(entry.Payload, &v) != nil || entry.Event.RecordID != rejectedConnectionID(v.Identity) || seen[v.OperationID] {
			return ErrEvidenceGap
		}
		if v.ThreadKey != domain.U64(p.key) {
			continue
		}
		seen[v.OperationID] = true
		if e := p.checkRejectedConnectionIdentity(v, decisions, entries); e != nil {
			return e
		}
	}
	return nil
}

// PruneRejectedConnections は7日満了した接続記録を既存の署名回収/物理圧縮で消す。
func PruneRejectedConnections(ctx context.Context, j *evidence.Journal, now domain.Time, held func(evidence.RequiredPostingIdentity, domain.Time) (bool, error)) (int, error) {
	if held == nil {
		return 0, store.ErrCorrupt
	}
	selectIdentity := func(entry evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if entry.Event.Kind != rejectedConnectionKind {
			return nil, nil
		}
		var v rejectedConnection
		if strictjson.Decode(entry.Payload, &v) != nil {
			return nil, store.ErrCorrupt
		}
		protected, e := held(v.Identity, now)
		if e != nil || protected {
			return nil, e
		}
		return &v.Identity, nil
	}
	return j.PruneRequired(now, selectIdentity, func(domain.ID, domain.Time) (bool, error) { return false, nil }, nil)
}

// RejectedConnectionPending は投稿以外の元列を解釈せず、接続行の存在だけを調べる。
func RejectedConnectionPending(j *evidence.Journal) bool {
	pending := false
	e := j.Visit(func(entry evidence.Entry) error {
		pending = pending || entry.Event.Kind == rejectedConnectionKind
		return nil
	})
	return pending || e != nil
}

func rejectedConnectionSourceValid(v rejectedConnection) bool {
	return v.Seq != 0 && v.Owner != (domain.ID{}) && v.Day != 0 && v.ThreadKey == v.Identity.ThreadKey && v.OperationID == v.Identity.OperationID
}

func rejectedConnectionReplayMatches(entry evidence.Entry, i evidence.RequiredPostingIdentity, v *rejectedConnection) bool {
	return entry.Event.Kind == rejectedConnectionKind && strictjson.Decode(entry.Payload, v) == nil && v.Identity == i
}

// checkRejectedConnectionIdentity は完全原本が残る間は両署名hashと接続観測まで一致させる。
func (p *PostingLog) checkRejectedConnectionIdentity(v rejectedConnection, decisions map[domain.ID]postingDecision, entries []evidence.Entry) error {
	proposal, found := p.proposals[v.OperationID]
	d, ok := decisions[v.OperationID]
	if !found || !ok || d.Outcome != "not_accepted" || !d.matches(proposal.payload, proposal.event) {
		return ErrEvidenceGap
	}
	if e := evidenceIdentityMatchesProposal(v.Identity, proposal.payload); e != nil {
		return e
	}
	if r, ok := p.retired[v.OperationID]; ok {
		if r.identity != v.Identity {
			return ErrEvidenceGap
		}
		return nil
	}
	return checkRejectedConnectionOriginal(v, proposal, entries)
}

func checkRejectedConnectionOriginal(v rejectedConnection, proposal proposalEntry, entries []evidence.Entry) error {
	for _, entry := range entries {
		if entry.Event.RecordID != v.Identity.DecisionID {
			continue
		}
		raw, e := json.Marshal(proposal.payload)
		if e != nil {
			return e
		}
		i, e := PostingRetirementIdentity(evidence.Entry{Event: proposal.event, Payload: raw}, entry)
		if e != nil || i != v.Identity {
			return ErrEvidenceGap
		}
		obs, e := evidence.PostingHTTPObservation(proposal.payload.Capture)
		if e != nil || !reflect.DeepEqual(obs, v.Observation) {
			return ErrEvidenceGap
		}
		return nil
	}
	return ErrEvidenceGap
}

// buildRejectedConnection は本文やprincipalを移さず、検証済みHTTP観測成分だけを取り出す。
func buildRejectedConnection(i evidence.RequiredPostingIdentity, capture []byte) (rejectedConnection, error) {
	obs, e := evidence.PostingHTTPObservation(capture)
	if e != nil {
		return rejectedConnection{}, e
	}
	v := rejectedConnection{ThreadKey: i.ThreadKey, OperationID: i.OperationID, Until: rejectedConnectionUntil(i), Identity: i, Observation: obs}
	if obs == nil {
		v.Missing = "not_collected"
	}
	return v, nil
}

// fillRejectedDecision は結果の実確定時刻と復旧確定の別を元署名から保持する。
func fillRejectedDecision(v *rejectedConnection, journals []*evidence.Journal) error {
	entry, found, e := findOriginalCandidate(journals, v.Identity.DecisionID)
	if e != nil {
		return e
	}
	var d postingDecision
	if !found || entry.Event.EventSHA != v.Identity.DecisionSHA || strictjson.Decode(entry.Payload, &d) != nil {
		return ErrEvidenceGap
	}
	v.Decided, v.Recovered = d.Decided, d.Recovered
	return nil
}
