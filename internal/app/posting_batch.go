// 同じスレッドの待機返信を非公開候補へ積み、三つの耐久境界を一括で通す。
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

// ErrPostingPrepared は内部候補の識別用。HTTPへ返す前に確定結果へ置換する。
var ErrPostingPrepared = errors.New("posting prepared for batch")

type preparedPosting struct {
	ctx      context.Context
	id       domain.ID
	op       domain.Operation
	frame    []byte
	proposal postingProposal
	next     *domain.Thread
	now      domain.Time
}

// PostingBatch は同じthread/journalだけを所有列上でまとめる非公開候補。
// 候補の採番・再送照合は次の候補へ見せるが、公開ゲートへは反映しない。
type PostingBatch struct {
	p              *PostingLog
	journal        *evidence.Journal
	posts          []*preparedPosting
	estimatedBytes int
	finished       bool
}

// Fits は最大64件と各Syncの8MiB上限を保守的な符号化予算で検査する。
// 大きい単独投稿・新規journal・別所有者は従来の個別保存へ戻す。
func (b *PostingBatch) Fits(p *PostingLog, frame, capture []byte) bool {
	if b.finished || p == nil || p.thread == nil || !p.active.BatchReady() || len(b.posts) >= store.MaxCommitFrames {
		return false
	}
	if b.p != nil && (b.p != p || b.journal != p.active) {
		return false
	}
	return 3*len(frame)+2*len(capture)+8192 <= (8<<20)-b.estimatedBytes
}

// Stage は完成frameを順番に検証して候補へ積む。保存開始前の取消はここでも拒否する。
// 成功時も耐久済みとはせず、Commit後に結果を置換するための識別子を返す。
func (b *PostingBatch) Stage(ctx context.Context, p *PostingLog, frame, capture []byte, now domain.Time) PostingResult {
	fail := func(e error) PostingResult {
		return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: e}}
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	if !b.Fits(p, frame, capture) || p.stopped || p.publicBlocked || p.PublicExpired(now) || (p.batch != nil && p.batch != b) {
		return fail(store.ErrCorrupt)
	}
	f, op, e := postingFrame(frame)
	if e != nil {
		return fail(e)
	}
	if op.Type != "append" {
		return fail(store.ErrCorrupt)
	}
	if result, found := p.findRetry(op.Dedup, now); found {
		return result
	}
	id := f.Records[0].ID
	if _, exists := p.proposals[id]; exists {
		return fail(errors.New("operation ID already used"))
	}
	for _, pending := range b.posts {
		if pending.id == id {
			return fail(errors.New("operation ID already used"))
		}
	}
	next, e := store.ValidateThreadFrame(p.postingState(), frame)
	if e != nil {
		return fail(e)
	}
	if now >= next.Expires {
		return fail(errors.New("thread expired"))
	}
	proposal := postingProposal{ThreadKey: domain.U64(p.key), OperationID: id, ThreadSeq: op.Revision, FrameSHA: sha256.Sum256(frame), Committed: op.Committed, Retention: postRetention(op.Committed), Frame: base64.StdEncoding.EncodeToString(frame), Capture: bytes.Clone(capture)}
	b.p, b.journal = p, p.active
	b.posts = append(b.posts, &preparedPosting{ctx, id, op, bytes.Clone(frame), proposal, next, now})
	b.estimatedBytes += 3*len(frame) + 2*len(capture) + 8192
	p.batch = b
	return PostingResult{CommitResult: store.CommitResult{Status: store.NotWritten, Err: ErrPostingPrepared}, OperationID: id, PostNumber: op.Dedup.PostNumber}
}

// postingState は所有列の次候補へだけ未確定状態を渡す。公開snapshotは交換しない。
func (p *PostingLog) postingState() *domain.Thread {
	if p.batch != nil && len(p.batch.posts) > 0 {
		return p.batch.posts[len(p.batch.posts)-1].next
	}
	return p.thread.State()
}

// Commit は全contextを保存直前に確認し、開始後の取消を無視して全結果を確定する。
// proposal→thread→decisionを各一回同期し、三境界の成功後だけ公開する。
func (b *PostingBatch) Commit() store.CommitResult {
	if b.finished || len(b.posts) == 0 {
		return store.CommitResult{Status: store.NotWritten, Err: store.ErrCorrupt}
	}
	b.finished = true
	p := b.p
	defer func() { p.batch = nil }()
	for _, pending := range b.posts {
		if e := pending.ctx.Err(); e != nil {
			return store.CommitResult{Status: store.NotWritten, Err: e}
		}
	}
	requests := make([]evidence.AppendRequest, len(b.posts))
	for i, pending := range b.posts {
		requests[i] = evidence.AppendRequest{ID: domain.NewID(), Kind: "evidence_proposal", Committed: pending.op.Committed, Build: func(src evidence.Source) ([]byte, error) {
			pending.proposal.Owner = src.Owner
			pending.proposal.Day = domain.U64(src.Subkey)
			pending.proposal.Seq = domain.U64(src.Seq)
			return json.Marshal(pending.proposal)
		}}
	}
	events, result := b.journal.AppendBatch(requests)
	if result.Status != store.Durable {
		if result.Status == store.Unknown {
			p.stopWriter()
		}
		return result
	}
	for i, pending := range b.posts {
		p.proposals[pending.id] = proposalEntry{pending.proposal, events[i]}
	}
	if result = p.after("proposal"); result.Status != store.Durable {
		return b.unknown(result)
	}
	frames := make([][]byte, len(b.posts))
	for i, pending := range b.posts {
		frames[i] = pending.frame
	}
	if result = p.thread.AppendBatch(frames); result.Status != store.Durable {
		return b.unknown(result)
	}
	if result = p.after("thread"); result.Status != store.Durable {
		return b.unknown(result)
	}
	for i, pending := range b.posts {
		entry := p.proposals[pending.id]
		prop := entry.payload
		requests[i] = evidence.AppendRequest{ID: domain.NewID(), Kind: "evidence_decision", Committed: pending.now, Build: func(src evidence.Source) ([]byte, error) {
			d := postingDecision{Owner: src.Owner, Day: domain.U64(src.Subkey), Seq: domain.U64(src.Seq), ThreadKey: prop.ThreadKey, OperationID: prop.OperationID, ThreadSeq: prop.ThreadSeq, FrameSHA: prop.FrameSHA, ProposalID: entry.event.RecordID, ProposalSHA: entry.event.EventSHA, Committed: prop.Committed, Retention: prop.Retention, Outcome: "accepted", Decided: pending.now}
			return json.Marshal(d)
		}}
	}
	if _, result = b.journal.AppendBatch(requests); result.Status != store.Durable {
		return b.unknown(result)
	}
	if result = p.after("decision"); result.Status != store.Durable {
		return b.unknown(result)
	}
	p.publish()
	return store.CommitResult{Status: store.Durable}
}

// unknown は保存開始後の失敗で公開を止め、再起動照合まで所有者を隔離する。
func (b *PostingBatch) unknown(result store.CommitResult) store.CommitResult {
	b.p.stopWriter()
	result.Status = store.Unknown
	return result
}

// IDs は確定結果の対応付けに使う候補IDを所有列上で返す。本文は返さない。
func (b *PostingBatch) IDs() []domain.ID {
	ids := make([]domain.ID, len(b.posts))
	for i, pending := range b.posts {
		ids[i] = pending.id
	}
	return ids
}

// Count は候補件数を返す。所有列の容量判断でID配列の複製を避ける。
func (b *PostingBatch) Count() int { return len(b.posts) }

// Discard は保存を始めていない候補を取り下げる。呼出元は受理/容量予約を返す。
func (b *PostingBatch) Discard() {
	if b.finished {
		return
	}
	b.finished = true
	if b.p != nil {
		b.p.batch = nil
	}
}
