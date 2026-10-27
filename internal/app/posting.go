// 単一スレッドの投稿WALと署名journalを連動させ、確定後だけ公開用snapshotを交換する。
package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// PostingSnapshot はprivateを含まない読み取り候補。DATは保存済みの公開byteのみ。
type PostingSnapshot struct {
	gate                                     *publicationGate
	epoch                                    uint64
	summary                                  ThreadSummary
	Title                                    string
	MoveTarget                               string
	DAT                                      []byte
	CanReply                                 bool
	CapOnly                                  bool
	PostCount                                uint32
	Expires                                  domain.Time
	Generation, Revision                     domain.U64
	Modified                                 domain.Time
	DateSafe, DateExact, LegacyRangeDisabled bool
}

// PostingResult は保存結果と元の操作を返す。Duplicateでも保持期限は延長しない。
type PostingResult struct {
	store.CommitResult
	OperationID domain.ID
	PostNumber  uint32
	Duplicate   bool
}

type proposalEntry struct {
	payload postingProposal
	event   evidence.Event
	compact bool
}

// PostingLog は板ワーカー内専用。journal・親ディレクトリの排他は呼出元が保持する。
// Repositoryの公開HTTP・停止中保守CLIから、板ワーカーを介して使用する。
type PostingLog struct {
	parent        string
	owner         domain.ID
	key           uint64
	thread        *store.ThreadLog
	reclaimed     *reclaimedBody
	active        *evidence.Journal
	proposals     map[domain.ID]proposalEntry
	retired       map[domain.ID]retiredPostingOriginals
	retiredFloor  domain.Time
	snapshot      *PostingSnapshot
	stopped       bool
	expired       bool
	publicBlocked bool
	gate          *publicationGate
	checkpoint    func(string) error
	expiryPersist func(domain.U64, domain.Time, domain.U64, domain.Time) error
	expirySaved   bool
	batch         *PostingBatch
}

// Post は事前検証→proposal Sync→thread Sync→decision Syncの順に保存する。
// frameは単一操作のみ。captureの秘密除去・HMAC生成・キー予約は呼出元の責務。
func (p *PostingLog) Post(ctx context.Context, prepared, capture []byte, now domain.Time) PostingResult {
	fail := func(e error) PostingResult {
		return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}
	}
	if p.stopped || p.expired || p.publicBlocked {
		return fail(errors.New("posting writer stopped or thread expired"))
	}
	if p.batch != nil {
		return fail(errors.New("posting batch pending"))
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	f, op, e := postingFrame(prepared)
	if e != nil {
		return fail(e)
	}
	return p.commitFrame(ctx, prepared, capture, now, f, op, false)
}

// commitFrame は利用者投稿と管理変更の署名/耐久性手順を共有する。
func (p *PostingLog) commitFrame(ctx context.Context, prepared, capture []byte, now domain.Time, f store.Frame, op domain.Operation, administrative bool) PostingResult {
	fail := func(e error) PostingResult {
		return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}
	}
	if p.stopped || p.expired {
		return fail(ErrEvidenceGap)
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if p.thread != nil {
		if now >= p.thread.State().Expires {
			p.expired = true
			return fail(errors.New("thread expired"))
		}
		if result, found := p.findRetry(op.Dedup, now); found {
			return result
		}
	}
	id := f.Records[0].ID
	prior, exists := p.proposals[id]
	if exists && (!administrative || prior.event.Kind != "thread_admin_proposal" || prior.payload.FrameSHA != sha256.Sum256(prepared)) {
		return fail(errors.New("operation ID already used"))
	}
	var old *domain.Thread
	if p.thread != nil {
		old = p.thread.State()
	}
	next, e := store.ValidateThreadFrame(old, prepared)
	if e != nil {
		return fail(e)
	}
	if now >= next.Expires {
		return fail(errors.New("thread expired"))
	}
	proposal := postingProposal{ThreadKey: domain.U64(p.key), OperationID: id, ThreadSeq: op.Revision, FrameSHA: sha256.Sum256(prepared), Committed: op.Committed, Retention: postRetention(op.Committed), Frame: base64.StdEncoding.EncodeToString(prepared), Capture: bytes.Clone(capture)}
	var event evidence.Event
	result := Commit(ctx, CommitSteps{
		Proposal: func() store.CommitResult {
			if exists {
				proposal, event = prior.payload, prior.event
				return store.CommitResult{Status: store.Durable}
			}
			var r store.CommitResult
			kind := "evidence_proposal"
			if administrative {
				kind = "thread_admin_proposal"
			}
			event, r = p.active.Append(domain.NewID(), kind, op.Committed, func(s evidence.Source) ([]byte, error) {
				proposal.Owner = s.Owner
				proposal.Day = domain.U64(s.Subkey)
				proposal.Seq = domain.U64(s.Seq)
				return json.Marshal(proposal)
			})
			if r.Status == store.Durable {
				p.proposals[id] = retainProposalEntry(proposal, event)
				return p.after("proposal")
			}
			return r
		},
		Thread: func() store.CommitResult {
			if p.thread == nil {
				var e error
				p.thread, e = store.CreateThread(p.parent, p.owner, p.key, prepared)
				if e != nil {
					return store.CommitResult{Status: store.Unknown, Err: e}
				}
			} else if r := p.thread.Append(prepared); r.Status != store.Durable {
				return r
			}
			return p.after("thread")
		},
		Decision: func() store.CommitResult {
			r := p.decide(proposalEntry{payload: proposal, event: event}, "accepted", false, now)
			if r.Status == store.Durable {
				return p.after("decision")
			}
			return r
		},
		Publish:            func() { p.publish() },
		StopWriter:         func() { p.stopWriter() },
		ReleaseReservation: func() {}, // 板の予約キー高水位を戻してはならない。
	})
	return PostingResult{CommitResult: result, OperationID: id, PostNumber: func() uint32 {
		if op.Dedup != nil {
			return op.Dedup.PostNumber
		}
		return 0
	}()}
}

func (p *PostingLog) after(stage string) store.CommitResult {
	if p.checkpoint != nil {
		if e := p.checkpoint(stage); e != nil {
			return store.CommitResult{Status: store.Unknown, Err: e}
		}
	}
	return store.CommitResult{Status: store.Durable}
}
func (p *PostingLog) decide(entry proposalEntry, outcome string, recovered bool, now domain.Time) store.CommitResult {
	prop := entry.payload
	d := postingDecision{ThreadKey: prop.ThreadKey, OperationID: prop.OperationID, ThreadSeq: prop.ThreadSeq, FrameSHA: prop.FrameSHA, ProposalID: entry.event.RecordID, ProposalSHA: entry.event.EventSHA, Committed: prop.Committed, Retention: prop.Retention, Outcome: outcome, Recovered: recovered, Decided: now}
	kind := "evidence_decision"
	if entry.event.Kind == "thread_admin_proposal" {
		kind = "thread_admin_decision"
	}
	_, r := p.active.Append(domain.NewID(), kind, now, func(s evidence.Source) ([]byte, error) {
		d.Owner = s.Owner
		d.Day = domain.U64(s.Subkey)
		d.Seq = domain.U64(s.Seq)
		return json.Marshal(d)
	})
	return r
}
func (p *PostingLog) publish() {
	if p.thread == nil {
		return
	}
	state := p.thread.State()
	if p.gate == nil {
		p.gate = &publicationGate{leases: map[*PublicLease]func(){}}
	}
	if state.After.State == "hidden" {
		p.snapshot = nil
		p.gate.mu.Lock()
		p.gate.hidden, p.gate.snapshot = true, nil
		p.gate.mu.Unlock()
		return
	}
	modified, dateSafe, dateExact := p.thread.PublicationDates()
	p.gate.mu.Lock()
	epoch := p.gate.epoch
	p.gate.mu.Unlock()
	p.snapshot = &PostingSnapshot{summary: ThreadSummary{Created: state.Created, State: state.After.State, Title: state.Title, Count: state.After.PostCount, BumpKind: state.After.BumpKind, BumpValue: state.After.BumpValue}, gate: p.gate, epoch: epoch, Title: state.Title, MoveTarget: state.MoveTarget, DAT: bytes.Join(state.Lines, nil), PostCount: state.After.PostCount, CanReply: state.After.State == "active", CapOnly: state.Policy.CapOnly, Expires: state.Expires,
		Generation: state.After.DATGeneration, Revision: state.Revision, Modified: modified, DateSafe: dateSafe, DateExact: dateExact, LegacyRangeDisabled: state.After.LegacyRangeDisabled}
	p.gate.mu.Lock()
	p.gate.hidden, p.gate.snapshot = false, p.snapshot
	p.gate.mu.Unlock()
}

// Snapshot は所有ワーカー内で呼び、期限内の確定済み公開状態のコピーだけを返す。
// 期限到達を観測したら失効を保持し、同じインスタンスで時計が逆行しても再公開しない。
func (p *PostingLog) Snapshot(now domain.Time) *PostingSnapshot {
	if p.PublicExpired(now) || p.publicBlocked || p.snapshot == nil {
		return nil
	}

	s := *p.snapshot
	s.DAT = bytes.Clone(s.DAT)
	return &s
}

// SharedSnapshot は所有ワーカー内で取得し、変更不能なDATを共有する公開HTTP用候補。
// 呼出元はDATを書き換えてはならず、送信前と送信中にPublicLeaseを検査する。
// publishは新しい配列へ交換するため、取得後の追記で旧候補が変化することはない。
func (p *PostingLog) SharedSnapshot(now domain.Time) *PostingSnapshot {
	if p.PublicExpired(now) || p.publicBlocked || p.snapshot == nil {
		return nil
	}
	s := *p.snapshot
	return &s
}

// Close はthread writerを停止する。共有journalは所有元で閉じる。
func (p *PostingLog) Close() error {
	p.blockPublication(true)
	p.stopWriter()
	if p.thread == nil {
		return nil
	}
	e := p.thread.Close()
	p.thread = nil
	return e
}

func (p *PostingLog) findRetry(want *domain.Dedup, now domain.Time) (PostingResult, bool) {
	if p.batch != nil {
		for _, pending := range p.batch.byThread[p] {
			op := pending.op
			r, found := retryRecord(store.ThreadRecord{ID: pending.id, Seq: op.Revision, FrameSHA: pending.proposal.FrameSHA, Type: op.Type, Committed: op.Committed, Dedup: op.Dedup}, want, now)
			if found {
				if r.Status == store.Durable {
					r.Status, r.Err = store.NotWritten, ErrPostingPrepared
				}
				return r, true
			}
		}
	}
	var records []store.ThreadRecord
	if p.thread != nil {
		if record, ok := p.thread.DedupRecord(want, now); ok {
			records = []store.ThreadRecord{record}
		}
	} else {
		records = p.records()
	}
	for _, record := range records {
		if result, ok := retryRecord(record, want, now); ok {
			if record.Dedup != nil && (p.reclaimed != nil || p.expired || p.thread.State().After.State == "hidden" || p.thread.State().Posts[record.Dedup.PostNumber-1].Visibility != "visible") {
				result.Status, result.Err = store.NotWritten, errors.New("deleted posting cannot be retried")
			}
			return result, true
		}
	}
	return PostingResult{}, false
}

func retryRecord(record store.ThreadRecord, want *domain.Dedup, now domain.Time) (PostingResult, bool) {
	d := record.Dedup
	if d == nil || want == nil || now >= d.Expires || d.Mode != want.Mode || d.KeyID != want.KeyID || d.Subject != want.Subject {
		return PostingResult{}, false
	}
	if d.Mode == "explicit" {
		if d.RequestID == nil || want.RequestID == nil || *d.RequestID != *want.RequestID {
			return PostingResult{}, false
		}
		if d.Request != want.Request {
			return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: errors.New("idempotency conflict")}}, true
		}
	} else if d.Request != want.Request {
		return PostingResult{}, false
	}
	return PostingResult{CommitResult: store.CommitResult{Status: store.Durable}, OperationID: record.ID, PostNumber: d.PostNumber, Duplicate: true}, true
}
