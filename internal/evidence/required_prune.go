// 必須投稿原本の満了を本文なし署名証跡へ置換し、元seq/hashと受理対応を保持する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

const requiredExpiryReason = "required_retention_expired"

// ErrRetirementClock は現在時刻が署名済み原本回収より前に戻ったことを示す。保存破損と区別する。
var ErrRetirementClock = errors.New("required evidence clock before signed retirement")

// RequiredPostingIdentity は原本回収後の復旧専用対応情報。本文・接続・主体は含めない。
// 所有者は元proposalとdecisionの完全照合後だけ作成する。
type RequiredPostingIdentity struct {
	ThreadKey   domain.U64  `json:"thread_key"`
	Type        string      `json:"operation_type"`
	OperationID domain.ID   `json:"operation_id"`
	ThreadSeq   domain.U64  `json:"thread_seq"`
	FrameSHA    domain.Hash `json:"thread_frame_sha256"`
	Committed   domain.Time `json:"committed_at_ns"`
	ProposalID  domain.ID   `json:"proposal_id"`
	ProposalSHA domain.Hash `json:"proposal_event_sha256"`
	DecisionID  domain.ID   `json:"decision_id"`
	DecisionSHA domain.Hash `json:"decision_event_sha256"`
	Outcome     string      `json:"decision"`
}

// RequiredRetirement は一つの元署名envelopeと本文なし対応情報を束縛する。
type RequiredRetirement struct {
	Seq      domain.U64              `json:"source_control_seq"`
	Envelope Event                   `json:"envelope_without_payload"`
	Until    domain.Time             `json:"retention_until_ns"`
	Identity RequiredPostingIdentity `json:"posting_identity"`
}

type requiredTombstone struct {
	Owner   domain.ID            `json:"source_owner_id"`
	Day     domain.U64           `json:"source_subkey"`
	Seq     domain.U64           `json:"source_control_seq"`
	At      domain.Time          `json:"removed_at_ns"`
	Reason  string               `json:"reason"`
	Removed []RequiredRetirement `json:"removed"`
}

func requiredKind(kind string) bool {
	return kind == "evidence_proposal" || kind == "evidence_decision" || kind == "rejected_connection"
}

// validateTombstone は理由別の完全型で検査する。未知理由を非必須型へ読み替えない。
func (j *Journal) validateTombstone(raw []byte) error {
	var marker struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(raw, &marker) != nil {
		return store.ErrCorrupt
	}
	if marker.Reason == requiredExpiryReason {
		_, e := j.decodeRequiredTombstone(raw)
		return e
	}
	_, e := j.decodeOptionalTombstone(raw)
	return e
}

// validateRemoval は所有者検証済み必須原本と既存の非必須完全型だけのnull変更を許す。
// 元連鎖と署名付き削除証跡の欠落はreplayで拒否する。
func (j *Journal) validateRemoval(kind, key string, old json.RawMessage) error {
	if !requiredKind(kind) {
		return validateOptionalRemoval(kind, key, old)
	}
	var event Event
	if strictjson.Decode(old, &event) != nil || event.RecordID.String() != key || event.Kind != kind {
		return store.ErrCorrupt
	}
	raw, e := decodePayload(event)
	if e != nil {
		return e
	}
	return j.validate(kind, raw)
}

// decodeRequiredTombstone は元envelopeの署名と所有者の本文なし対応型を照合する。
func (j *Journal) decodeRequiredTombstone(raw []byte) (requiredTombstone, error) {
	var t requiredTombstone
	if strictjson.Decode(raw, &t) != nil || t.Owner != j.owner || uint64(t.Day) != j.day || t.Seq == 0 || t.At <= 0 || t.Reason != requiredExpiryReason || len(t.Removed) == 0 || len(t.Removed) > 128 {
		return t, store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, r := range t.Removed {
		if seen[r.Envelope.RecordID] || r.Seq >= t.Seq || r.Until > t.At {
			return t, store.ErrCorrupt
		}
		if e := j.validateRequiredRetirement(r); e != nil {
			return t, e
		}
		seen[r.Envelope.RecordID] = true
	}
	return t, nil
}

// validateRequiredRetirement はpayloadなし元署名を検証し、保持期限の業務規則を所有者へ渡す。
func (j *Journal) validateRequiredRetirement(r RequiredRetirement) error {
	e := r.Envelope
	if r.Seq == 0 || r.Until <= 0 || e.Payload != "" || e.Schema != "evidence-v1" || !requiredKind(e.Kind) || e.RecordID == (domain.ID{}) || e.SigningKeyID != j.keyID {
		return store.ErrCorrupt
	}
	if digest(Source{j.owner, j.day, uint64(r.Seq)}, e.RecordID, e.Kind, e.PayloadSHA, e.PreviousSHA) != e.EventSHA {
		return store.ErrCorrupt
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(signature) != e.Signature || !ed25519.Verify(j.key.Public().(ed25519.PublicKey), e.EventSHA[:], signature) {
		return store.ErrCorrupt
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return j.validate("required_retirement", raw)
}

// addRemoved は理由別に削除envelopeを元連鎖へ戻す。元payloadは復元しない。
func (j *Journal) addRemoved(chain map[uint64]Event, raw []byte) error {
	var marker struct {
		Reason string `json:"reason"`
	}
	if json.Unmarshal(raw, &marker) != nil {
		return store.ErrCorrupt
	}
	if marker.Reason != requiredExpiryReason {
		return j.addOptionalRemoved(chain, raw)
	}
	t, e := j.decodeRequiredTombstone(raw)
	if e != nil {
		return e
	}
	if t.At > j.requiredFloor {
		j.requiredFloor = t.At
	}
	for _, r := range t.Removed {
		if _, exists := chain[uint64(r.Seq)]; exists || j.ids[r.Envelope.RecordID] {
			return store.ErrCorrupt
		}
		chain[uint64(r.Seq)] = r.Envelope
		j.ids[r.Envelope.RecordID] = true
	}
	return nil
}

// RequiredRetirements は検証済み必須削除証跡から独立した復旧対応情報を返す。
// 通常照会の原本や提出証拠として使用しない。
func (j *Journal) RequiredRetirements() ([]RequiredRetirement, error) {
	if j.stopped {
		return nil, store.ErrIncomplete
	}
	result := []RequiredRetirement{}
	for _, entry := range j.entries {
		if entry.Event.Kind != "tombstone" {
			continue
		}
		var marker struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(entry.Payload, &marker) != nil {
			return nil, store.ErrCorrupt
		}
		if marker.Reason != requiredExpiryReason {
			continue
		}
		t, e := j.decodeRequiredTombstone(entry.Payload)
		if e != nil {
			return nil, e
		}
		result = append(result, t.Removed...)
	}
	return result, nil
}

// RequiredRetirementFloor は署名済み必須削除証跡/日末確認の最大時刻を返す。元期限とは区別する。
// 起動時の連鎖検証で復元し、停止列では利用を拒否する。原本文を走査・複製しない。
func (j *Journal) RequiredRetirementFloor() (domain.Time, error) {
	if j.stopped {
		return 0, store.ErrIncomplete
	}
	return j.requiredFloor, nil
}

// PruneRequired は最大128行の署名済み保持期限満了原本を、対応情報を持つ証跡へ置換する。
// 同じ所有排他内でselectIdentityによる受理対応とheldによる耐久保全予約を必ず照合する。
// nil選択は保持、予約照合失敗は全件非変更。製品はreader更新と復旧対応の接続後だけ呼び出す。
func (j *Journal) PruneRequired(now domain.Time, selectIdentity func(Entry) (*RequiredPostingIdentity, error), held func(domain.ID, domain.Time) (bool, error), boundary func(string) error) (int, error) {
	if j.stopped || now <= 0 || selectIdentity == nil || held == nil {
		return 0, store.ErrCorrupt
	}
	if now < j.requiredFloor {
		return 0, ErrRetirementClock
	}
	if boundary == nil {
		boundary = func(string) error { return nil }
	}
	if e := j.resumeOptionalPrune(); e != nil {
		return 0, e
	}
	t, changes, e := j.selectRequiredRetirements(now, selectIdentity, held)
	if e != nil || len(changes) == 0 {
		return 0, e
	}
	return j.commitRequiredRetirements(t, changes, boundary)
}

// selectRequiredRetirements は保存済み期限・元対応・保全予約を全候補で確認してから変更を構築する。
func (j *Journal) selectRequiredRetirements(now domain.Time, selectIdentity func(Entry) (*RequiredPostingIdentity, error), held func(domain.ID, domain.Time) (bool, error)) (requiredTombstone, []store.Mutation, error) {
	t := requiredTombstone{j.owner, domain.U64(j.day), domain.U64(j.seq + 1), now, requiredExpiryReason, []RequiredRetirement{}}
	changes := []store.Mutation{}
	for _, entry := range j.entries {
		r, e := j.selectRequiredRetirement(entry, now, selectIdentity, held)
		if e != nil {
			return t, nil, e
		}
		if r == nil {
			continue
		}
		t.Removed = append(t.Removed, *r)
		changes = append(changes, store.Mutation{Collection: r.Envelope.Kind, Key: r.Envelope.RecordID.String(), ExpectedRevision: r.Seq, Value: json.RawMessage("null")})
		if len(changes) == 128 {
			break
		}
	}
	return t, changes, nil
}

// selectRequiredRetirement は一行の満了/予約/所有者対応を検査し、保持行ではnilを返す。
func (j *Journal) selectRequiredRetirement(entry Entry, now domain.Time, selectIdentity func(Entry) (*RequiredPostingIdentity, error), held func(domain.ID, domain.Time) (bool, error)) (*RequiredRetirement, error) {
	if !requiredKind(entry.Event.Kind) {
		return nil, nil
	}
	var source struct {
		Seq   domain.U64  `json:"source_control_seq"`
		Until domain.Time `json:"retention_until_ns"`
	}
	if json.Unmarshal(entry.Payload, &source) != nil || source.Seq == 0 || source.Until <= 0 {
		return nil, store.ErrCorrupt
	}
	identity, e := selectIdentity(Entry{entry.Event, bytes.Clone(entry.Payload)})
	if e != nil || identity == nil {
		return nil, e
	}
	until := source.Until
	if entry.Event.Kind != "rejected_connection" {
		until = RequiredOriginalDeadline(*identity, source.Until)
	}
	if until > now {
		return nil, nil
	}
	protected, e := held(entry.Event.RecordID, now)
	if e != nil || protected {
		return nil, e
	}
	event := entry.Event
	event.Payload = ""
	r := RequiredRetirement{source.Seq, event, until, *identity}
	if e = j.validateRequiredRetirement(r); e != nil {
		return nil, e
	}
	if e = matchesRequiredOriginal(entry.Payload, r); e != nil {
		return nil, e
	}
	return &r, nil
}

// matchesRequiredOriginal は本文を複製せず、回収前の対応情報が実原本と一致することを確認する。
func matchesRequiredOriginal(raw []byte, r RequiredRetirement) error {
	if r.Envelope.Kind == "rejected_connection" {
		var v struct {
			Identity RequiredPostingIdentity `json:"posting_identity"`
		}
		if json.Unmarshal(raw, &v) != nil || v.Identity != r.Identity {
			return store.ErrCorrupt
		}
		return nil
	}
	var p struct {
		ThreadKey   domain.U64  `json:"thread_key"`
		OperationID domain.ID   `json:"operation_id"`
		ThreadSeq   domain.U64  `json:"thread_seq"`
		FrameSHA    domain.Hash `json:"thread_frame_sha256"`
		Committed   domain.Time `json:"committed_at_ns"`
		ProposalID  domain.ID   `json:"proposal_id"`
		ProposalSHA domain.Hash `json:"proposal_event_sha256"`
		Outcome     string      `json:"decision"`
	}
	if json.Unmarshal(raw, &p) != nil {
		return store.ErrCorrupt
	}
	i := r.Identity
	if i.ThreadKey != p.ThreadKey || i.OperationID != p.OperationID || i.ThreadSeq != p.ThreadSeq || i.FrameSHA != p.FrameSHA || i.Committed != p.Committed {
		return store.ErrCorrupt
	}
	if r.Envelope.Kind == "evidence_decision" && (i.ProposalID != p.ProposalID || i.ProposalSHA != p.ProposalSHA || i.Outcome != p.Outcome) {
		return store.ErrCorrupt
	}
	return nil
}

// commitRequiredRetirements は削除と証跡を一つのSync frameにし、検証済みsnapshotから全旧世代を回収する。
func (j *Journal) commitRequiredRetirements(t requiredTombstone, changes []store.Mutation, boundary func(string) error) (int, error) {
	raw, e := json.Marshal(t)
	if e != nil {
		return 0, e
	}
	id := domain.NewID()
	event, e := Seal(Source{j.owner, j.day, j.seq + 1}, id, "tombstone", raw, j.entries[len(j.entries)-1].Event.EventSHA, j.keyID, j.key)
	if e != nil {
		return 0, e
	}
	value, e := json.Marshal(event)
	if e != nil {
		return 0, e
	}
	changes = append(changes, store.Mutation{Collection: "tombstone", Key: id.String(), Value: value})
	op := store.ControlOperation{Schema: 1, Seq: t.Seq, ExpectedSeq: domain.U64(j.seq), Committed: t.At, Actor: domain.Actor{Kind: "system", Reason: requiredExpiryReason}, Mutations: changes, Result: store.ControlResult{Code: requiredExpiryReason, Targets: []string{}}}
	opRaw, e := json.Marshal(op)
	if e != nil {
		return 0, e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: j.seq + 1, Records: []store.Record{{ID: id, JSON: opRaw}}})
	if e != nil {
		return 0, e
	}
	result := j.log.Append(frame)
	if result.Status != store.Durable {
		if result.Status == store.Unknown {
			j.stopped = true
		}
		return 0, result.Err
	}
	count := len(t.Removed)
	if e = j.replay(); e == nil {
		e = boundary("required:removed")
	}
	if e == nil {
		e = j.compactOptional(func(stage string) error {
			return boundary("required:" + stage[len("optional:"):])
		})
	}
	if e != nil {
		j.stopped = true
	}
	return count, e
}

// RequiredOriginalDeadline は確定未受理原本だけを24時間期限へ短縮する。
// 未決定・受理済みは署名原本の期限を保持し、加算不能な時計は短縮しない。
func RequiredOriginalDeadline(i RequiredPostingIdentity, original domain.Time) domain.Time {
	if i.Outcome == "not_accepted" && i.Committed > 0 && i.Committed <= domain.Time(math.MaxInt64)-domain.Time(24*time.Hour) {
		return min(original, i.Committed+domain.Time(24*time.Hour))
	}
	return original
}
