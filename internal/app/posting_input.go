// 正規化済み入力から、所有ワーカー内で最新状態に対する投稿候補を生成する。
package app

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
)

// PreparePost は状態を外へ渡さず採番・上限判定する。所有ワーカー専用。
func (p *PostingLog) PreparePost(input postinput.Input, c postinput.BuildContext) ([]byte, error) {
	if p.stopped || p.publicBlocked || p.thread == nil || p.expired {
		return nil, postinput.ErrInput
	}
	if p.PublicExpired(domain.Time(c.Now.UnixNano())) {
		return nil, postinput.ErrInput
	}
	return postinput.Build(p.postingState(), input, c)
}

// BumpValue は板内の次の順位採番に使う。非公開投稿内容は返さない。
func (p *PostingLog) BumpValue() domain.U64 {
	if p.reclaimed != nil {
		return p.reclaimed.proof.After.BumpValue
	}
	if p.thread == nil {
		return 0
	}
	return p.postingState().After.BumpValue
}

// Retry は構築前にも確定済み再送を照合する。件数終了後の最終投稿再送を許す。
func (p *PostingLog) Retry(want *domain.Dedup, now domain.Time) (PostingResult, bool) {
	if p.stopped || p.thread == nil && p.reclaimed == nil {
		return PostingResult{}, false
	}
	// 公開失効後も元の要求IDを照合する。成功には戻さず再作成を拒否する。
	p.PublicExpired(now)
	if p.stopped || p.publicBlocked && !p.expired && p.thread.State().After.State != "hidden" {
		return PostingResult{}, false
	}
	return p.findRetry(want, now)
}

// ExplicitDedups は復旧時の板全体の明示再送ID重複検査用。所有ワーカー専用。
func (p *PostingLog) ExplicitDedups(now domain.Time) []*domain.Dedup {
	if p.thread == nil && p.reclaimed == nil {
		return nil
	}
	var out []*domain.Dedup
	for _, r := range p.records() {
		if r.Dedup != nil && r.Dedup.Mode == "explicit" && now < r.Dedup.Expires {
			d := *r.Dedup
			id := *d.RequestID
			d.RequestID = &id
			out = append(out, &d)
		}
	}
	return out
}

// PostingPolicy は確認に必要な公開条件だけを所有ワーカーへ返す。終了スレの再送確認も許す。
// 期限切れはラッチし、時計が戻っても確認経路から復活させない。
func (p *PostingLog) PostingPolicy(now domain.Time) (domain.Policy, bool) {
	if p.stopped || p.publicBlocked || p.thread == nil || p.expired {
		return domain.Policy{}, false
	}
	if p.PublicExpired(now) {
		return domain.Policy{}, false
	}
	if p.thread.State().After.State == "hidden" {
		return domain.Policy{}, false
	}
	policy := p.thread.State().Policy
	policy.Commands = append([]string{}, policy.Commands...)
	return policy, true
}

// PublicExpired は公開期限の到達を通知する。記録だけの未受理スレッドは存在扱いにしない。
func (p *PostingLog) PublicExpired(now domain.Time) bool {
	if p.reclaimed != nil {
		return true
	}
	if p.thread == nil {
		return false
	}
	if p.expired || now >= p.thread.State().Expires || p.publicationExpired() {
		p.expired = true
		p.blockPublication(true)
		p.snapshot = nil
		if !p.expirySaved && p.expiryPersist != nil {
			s := p.thread.State()
			// 送信側で失効を観測した後の時計逆行でも、元期限を下回る台帳を作らない。
			if e := p.expiryPersist(s.Revision, s.Expires, s.Policy.Version, max(now, s.Expires)); e != nil {
				p.stopWriter()
			} else {
				p.expirySaved = true
			}
		}
	}
	return p.expired
}

// SetExpiryPersistence は期限到達を所有列内で耐久保存する処理を設定する。
// callbackは同じPostingLogを再入せず、失敗時は公開とwriterを停止する。
func (p *PostingLog) SetExpiryPersistence(save func(domain.U64, domain.Time, domain.U64, domain.Time) error) {
	p.expiryPersist = save
}

// RestoreExpired は耐久台帳の公開停止を復元する。時計が戻っても解除しない。
func (p *PostingLog) RestoreExpired() {
	p.expired, p.expirySaved = true, true
	p.blockPublication(true)
	p.snapshot = nil
}

// RetentionState は期限管理用の本文なし状態を返す。期限後も照合できる。
func (p *PostingLog) RetentionState() (seq domain.U64, expires domain.Time, policy domain.U64, ok bool) {
	if p.reclaimed != nil {
		v := p.reclaimed.proof
		return v.Sequence, v.Expires, v.Policy.Version, true
	}
	if p.thread == nil {
		return 0, 0, 0, false
	}
	s := p.thread.State()
	return s.Revision, s.Expires, s.Policy.Version, true
}

// ThreadSummary は一覧に必要な公開項目だけを持ち、DATやprivateを複製しない。
type ThreadSummary struct {
	Created   domain.Time
	State     string
	Title     string
	Count     uint32
	BumpKind  string
	BumpValue domain.U64
}

// Summary は所有ワーカー内で、公開可能な確定スレッドだけを要約する。
func (p *PostingLog) Summary(now domain.Time) *ThreadSummary {
	if p.PublicExpired(now) || p.publicBlocked || p.snapshot == nil || p.thread == nil {
		return nil
	}
	state := p.thread.State()
	return &ThreadSummary{Created: state.Created, State: state.After.State, Title: p.snapshot.Title, Count: p.snapshot.PostCount, BumpKind: state.After.BumpKind, BumpValue: state.After.BumpValue}
}
