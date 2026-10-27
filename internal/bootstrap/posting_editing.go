// フォーム表示の公開確認・投稿条件・CSRF発行を所有列で一度に行い、返信の保存境界を増やさない。
package bootstrap

import (
	"errors"
	"oimobbs/internal/domain"
)

var errEditingThreadGone = errors.New("editing thread unavailable")

// editingForm は未保存の表示結果。投稿の受理結果や未確定DATは含まない。
type editingForm struct {
	page postingPage
	csrf WebCSRFForm
}

// prepareEditing は所有列で確定済みの公開条件を確認し、保存不要のフォーム値を作る。
// 同じスレッドの返信batch内でも候補を公開せず、削除・期限・停止・Cookieの検査を保つ。
func (b *postingBoard) prepareEditing(key uint64, route, existing string, secure bool) (editingForm, error) {
	if b.stopped {
		return editingForm{}, ErrPostingUnavailable
	}
	board, err := b.postingFormSettings()
	if err != nil {
		return editingForm{}, err
	}
	policy := board.Settings.Posting.Create
	if key != 0 {
		p := b.threads[key]
		if p == nil || p.SharedSnapshot(domain.Time(b.clock().UnixNano())) == nil {
			return editingForm{}, errEditingThreadGone
		}
		policy = board.Settings.Posting.Reply
		if policy == "disabled" {
			policy = "command_only"
		}
		if saved, ok := p.PostingPolicy(domain.Time(b.clock().UnixNano())); ok && saved.CapOnly && policy != "command_only" {
			policy = "cap_only"
		}
	}
	form := editingForm{page: postingPage{Input: board.Settings.Input, PostingPolicy: policy}}
	if policy == "disabled" {
		return form, nil
	}
	form.csrf, err = b.makeWebCSRF(route, existing, secure)
	return form, err
}
