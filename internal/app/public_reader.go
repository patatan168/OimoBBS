// 確定済み公開状態を保存列の外で読み、既存の送信失効ゲートへ接続する。
package app

import "oimobbs/internal/domain"

// PublicReader は変更不能な公開DATの参照。投稿・非公開の所有状態には触れない。
type PublicReader struct{ gate *publicationGate }

// PublicReader は所有列内で取得する。以後Snapshotは投稿と並行して呼べる。
func (p *PostingLog) PublicReader() *PublicReader {
	if p.gate == nil {
		p.gate = &publicationGate{leases: map[*PublicLease]func(){}}
	}
	g := p.gate
	g.mu.Lock()
	g.expired = g.expired || p.expired || p.reclaimed != nil
	g.blocked = g.blocked || p.publicBlocked || p.stopped
	g.mu.Unlock()
	return &PublicReader{gate: g}
}

// Snapshot は確定済み候補とHTTP状態を返す。DATは変更せず、送信時にリースを取得する。
// 期限到達は即時にラッチして送信を停止する。耐久期限台帳の保存は所有列が行う。
func (r *PublicReader) Snapshot(now domain.Time) (*PostingSnapshot, int) {
	g := r.gate
	g.mu.Lock()
	if s := g.snapshot; s != nil && now >= s.Expires && !g.expired {
		callbacks := g.expireLocked()
		g.mu.Unlock()
		for _, f := range callbacks {
			f()
		}
		return nil, 410
	}
	defer g.mu.Unlock()
	if g.expired || g.hidden {
		return nil, 410
	}
	if g.blocked {
		return nil, 503
	}
	if g.snapshot == nil {
		return nil, 404
	}
	snapshot := *g.snapshot
	return &snapshot, 200
}

// stopWriter は保存結果が不明な所有者の公開と投稿を一緒に停止する。
func (p *PostingLog) stopWriter() {
	p.stopped = true
	p.setPublicationBlocked(true)
}
