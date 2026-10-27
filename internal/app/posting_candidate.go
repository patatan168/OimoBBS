// 不変な投稿前状態に束縛した検証済み候補を、CPU構築から所有列へ引き渡す。
package app

import (
	"bytes"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
)

// PreparedPosting は私的な元frame・復号結果・次状態を持つ一呼出し専用の候補。
// 元状態を不変に保ち、保存層では元frameを引き続き完全再検証する。
type PreparedPosting struct {
	thread         *store.ThreadLog
	previousHash   domain.Hash
	log            *PostingLog
	previous, next *domain.Thread
	raw            []byte
	frame          store.Frame
	op             domain.Operation
	rate           RateRecord
}

// Frame は元byteの複製を返す。呼出元の改変はMatchesと保存前の検証で拒否する。
func (c *PreparedPosting) Frame() []byte { return bytes.Clone(c.raw) }

// Matches は構築時の元byteとの完全一致を検査する。
func (c *PreparedPosting) Matches(raw []byte) bool { return c != nil && bytes.Equal(c.raw, raw) }

// Metadata は構築中に完全検証した成分を所有列へ借用する。slice・pointerの変更は禁止。
func (c *PreparedPosting) Metadata() (store.Frame, domain.Operation, RateRecord) {
	return c.frame, c.op, c.rate
}

// PreparePostingWork は所有列で期限・停止を検査し、その状態だけを読む独立構築処理を返す。
// 全work終了まで所有列で候補を更新しない。返す元byte・操作・次状態は同じ構築呼出し専用。
// 期限到達時は登録済みの永続化も所有列で実行する。
func (p *PostingLog) PreparePostingWork(input postinput.Input, c postinput.BuildContext) (func() (*PreparedPosting, error), error) {
	if p.stopped || p.publicBlocked || p.thread == nil || p.expired || p.PublicExpired(domain.Time(c.Now.UnixNano())) {
		return nil, postinput.ErrInput
	}
	old := p.postingState()
	thread := p.thread
	_, previousHash, ok := p.postingSourceIdentity()
	if !ok {
		return nil, store.ErrCorrupt
	}
	return func() (*PreparedPosting, error) {
		built, err := postinput.BuildPrepared(old, input, c)
		if err != nil {
			return nil, err
		}
		raw, f, op, next := built.Raw, built.Frame, built.Operation, built.Next
		rate, err := parsedFrameRateRecord(f, op)
		if err != nil {
			return nil, err
		}
		return &PreparedPosting{thread: thread, previousHash: previousHash, log: p, previous: old, next: next, raw: raw, frame: f, op: op, rate: rate}, nil
	}, nil
}

// postingSourceIdentity は未公開候補または正本の最終frameで論理状態を識別する。
func (p *PostingLog) postingSourceIdentity() (domain.U64, domain.Hash, bool) {
	if p.batch != nil && p.batch.next[p] != nil {
		posts := p.batch.byThread[p]
		if len(posts) > 0 {
			last := posts[len(posts)-1]
			return last.op.Revision, last.proposal.FrameSHA, true
		}
		return 0, domain.Hash{}, false
	}
	if p.thread == nil {
		return 0, domain.Hash{}, false
	}
	return p.thread.LastRecordIdentity()
}

// matchesSource は同期で同じ状態が別objectへ再生されても、別の履歴分岐へは流用しない。
func (c *PreparedPosting) matchesSource(p *PostingLog) bool {
	if c.log != p || c.thread != p.thread || c.previous == nil {
		return false
	}
	if c.previous == p.postingState() {
		return true
	}
	seq, hash, ok := p.postingSourceIdentity()
	return ok && seq == c.previous.Revision && hash == c.previousHash
}
