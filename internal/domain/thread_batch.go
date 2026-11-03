// 一括処理の履歴領域を一度だけ複製し、全操作の検算後にだけ候補を渡す。
package domain

import "oimobbs/internal/strictjson"

// ThreadBatch は一所有者専用の未公開候補。コピー・並行使用は禁止する。
// 各操作は通常のApplyと同じ検査を行う。失敗後とFinish後は再使用できない。
type ThreadBatch struct {
	state  *Thread
	owned  bool
	closed bool
}

// NewThreadBatch は不変の元状態を借用する。最初の操作で履歴を切り離す。
// Finishまで元状態を変更せず、候補の参照を外部へ渡さないこと。
func NewThreadBatch(old *Thread) *ThreadBatch { return &ThreadBatch{state: old} }

// ApplyEncoded は完全スキーマ・業務制約・DAT・遷移後状態を逐次検算する。
// 群内の中間状態は公開せず、失敗した群は以後Finishでも受け取れない。
func (b *ThreadBatch) ApplyEncoded(raw, dat []byte) (Operation, error) {
	var op Operation
	if b.closed {
		return op, ErrOperation
	}
	err := strictjson.Decode(raw, &op)
	if err == nil {
		var next *Thread
		next, err = apply(b.state, op, dat, !b.owned)
		if err == nil {
			b.state, b.owned = next, true
			return op, nil
		}
	}
	b.state, b.closed = nil, true
	return op, err
}

// Finish は全操作が成功した候補の所有権を一度だけ返す。保存・公開は呼出元が行う。
func (b *ThreadBatch) Finish() (*Thread, error) {
	if b.closed || !b.owned {
		b.state, b.closed = nil, true
		return nil, ErrOperation
	}
	next := b.state
	b.state, b.closed = nil, true
	return next, nil
}
