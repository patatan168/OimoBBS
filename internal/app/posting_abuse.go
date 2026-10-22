// 荒らし検出用の直近公開投稿を所有列へ渡し、削除済み本文を新たな索引へ戻さない。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

// AbusePostVisible は所有ワーカー内で、削除・非公開・期限切れの検出索引を無効にする。
// 期限の永続処理は起動せず、検出器のmutexの下でも再入しない。
func (p *PostingLog) AbusePostVisible(number uint32, now domain.Time) bool {
	if p.expired || p.publicBlocked || p.thread == nil || p.publicationExpired() || now >= p.thread.State().Expires {
		return false
	}
	state := p.thread.State()
	return state.After.State != "hidden" && number > 0 && int(number) <= len(state.Posts) && state.Posts[number-1].Visibility == "visible"
}

// VisitRecentAbusePosts は確定済み現在本文と照合済みCookie主体を復旧専用callbackへ渡す。
// sinceより古い投稿は走査を打ち切る。callbackは参照を保存せず、同じPostingLogを変更しない。
func (p *PostingLog) VisitRecentAbusePosts(now, since domain.Time, visit func(domain.ID, domain.Post, *postcapture.TokenEvidence)) error {
	if p.thread == nil || p.thread.State().After.State == "hidden" || p.expired || p.publicBlocked || now >= p.thread.State().Expires {
		return nil
	}
	posts := p.thread.State().Posts
	records := p.records()
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if record.Committed < since {
			break
		}
		if record.Type != "create" && record.Type != "append" {
			continue
		}
		entry, ok := p.proposals[record.ID]
		if !ok {
			return ErrEvidenceGap
		}
		raw, err := entry.decodeFrame()
		if err != nil {
			return ErrEvidenceGap
		}
		rate, err := FrameRateRecord(raw)
		if err != nil || rate.ID != record.ID || rate.At != record.Committed {
			return ErrEvidenceGap
		}
		if rate.PostNumber == 0 || int(rate.PostNumber) > len(posts) {
			return ErrEvidenceGap
		}
		post := posts[rate.PostNumber-1]
		if post.Kind != "user" || post.Visibility != "visible" || post.Private == nil {
			continue
		}
		capture, err := entry.originalCapture()
		if err != nil {
			return err
		}
		_, _, token, err := postcapture.TokenMetadata(capture)
		if err != nil {
			return err
		}
		visit(record.ID, post, token)
	}
	return nil
}
