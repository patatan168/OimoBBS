// 公開snapshotの失効世代を、所有列外の送信リースへ伝える。
package app

import (
	"errors"
	"oimobbs/internal/domain"
	"sync"
)

// ErrPublicationGone は削除・期限到達によって送信権限が失効したことを表す。
var ErrPublicationGone = errors.New("publication lease revoked")

type publicationGate struct {
	mu       sync.Mutex
	epoch    uint64
	blocked  bool
	expired  bool
	hidden   bool
	snapshot *PostingSnapshot
	leases   map[*PublicLease]func()
}

// PublicLease はsnapshotの公開世代と期限へ束縛した送信資源。送信後はCloseが必要。
// Checkは各送信片の直前に呼ぶ。失効時のcallbackは本文送信を中断する。
type PublicLease struct {
	gate    *publicationGate
	epoch   uint64
	expires domain.Time
	closed  bool
}

// AcquirePublic は所有列で取得したsnapshotが今も公開可能か確認してリースを登録する。
// revokeは削除と期限到達時に呼ぶ。通知中に同じgateを操作してはならない。
func (s *PostingSnapshot) AcquirePublic(now domain.Time, revoke func()) (*PublicLease, error) {
	if s == nil || s.gate == nil {
		return nil, ErrPublicationGone
	}
	g := s.gate
	g.mu.Lock()
	callbacks := []func(){}
	if now >= s.Expires && !g.expired && !g.blocked && g.epoch == s.epoch {
		callbacks = g.expireLocked()
	}
	if g.blocked || g.expired || g.epoch != s.epoch || now >= s.Expires {
		g.mu.Unlock()
		for _, f := range callbacks {
			f()
		}
		return nil, ErrPublicationGone
	}
	l := &PublicLease{gate: g, epoch: s.epoch, expires: s.Expires}
	g.leases[l] = revoke
	g.mu.Unlock()
	return l, nil
}

// Check は削除・期限・Closeを確認する。期限を観測したgateは時計逆行で復活しない。
func (l *PublicLease) Check(now domain.Time) error {
	if l == nil {
		return ErrPublicationGone
	}
	g := l.gate
	g.mu.Lock()
	invalid := l.closed || g.blocked || g.expired || g.epoch != l.epoch || now >= l.expires
	expired := now >= l.expires && !g.expired && !l.closed && !g.blocked && g.epoch == l.epoch
	callbacks := []func(){}
	if expired {
		callbacks = g.expireLocked()
	}
	g.mu.Unlock()
	for _, f := range callbacks {
		f()
	}
	if invalid {
		return ErrPublicationGone
	}
	return nil
}

// expireLocked は失効を一度だけラッチし、gate解放後に通知するcallbackを取り出す。
func (g *publicationGate) expireLocked() []func() {
	g.expired = true
	g.snapshot = nil
	g.epoch++
	callbacks := []func(){}
	for lease, f := range g.leases {
		if f != nil {
			callbacks = append(callbacks, f)
		}
		delete(g.leases, lease)
	}
	return callbacks
}

// Close は送信完了後にcallbackとリースを解放する。複数回呼んでも安全。
func (l *PublicLease) Close() {
	if l == nil {
		return
	}
	g := l.gate
	g.mu.Lock()
	delete(g.leases, l)
	l.closed = true
	g.mu.Unlock()
}

func (p *PostingLog) blockPublication(blocked bool) {
	p.publicBlocked = blocked
	p.setPublicationBlocked(blocked)
}

// setPublicationBlocked は送信ゲートだけを変更し、所有列の保存済み候補は保つ。
func (p *PostingLog) setPublicationBlocked(blocked bool) {
	if p.gate == nil {
		p.gate = &publicationGate{leases: map[*PublicLease]func(){}}
	}
	g := p.gate
	g.mu.Lock()
	g.blocked = blocked
	g.expired = g.expired || p.expired
	callbacks := []func(){}
	if blocked {
		g.snapshot = nil
		g.epoch++
		for l, f := range g.leases {
			if f != nil {
				callbacks = append(callbacks, f)
			}
			delete(g.leases, l)
		}
	}
	g.mu.Unlock()
	for _, f := range callbacks {
		f()
	}
}

// publicationExpired は送信側で観測した期限到達も所有列の期限ラッチへ引き継ぐ。
func (p *PostingLog) publicationExpired() bool {
	if p.gate == nil {
		return false
	}
	p.gate.mu.Lock()
	defer p.gate.mu.Unlock()
	return p.gate.expired
}

// PublicationSnapshot は一覧送信用の世代と期限だけを返す。DATを複製しない。
// 所有列内で要約と同時に取得し、実際の送信前にAcquirePublicで検査する。
func (p *PostingLog) PublicationSnapshot(now domain.Time) *PostingSnapshot {
	if p.PublicStatus(now) != 200 || p.snapshot == nil {
		return nil
	}
	return &PostingSnapshot{gate: p.gate, epoch: p.snapshot.epoch, Expires: p.snapshot.Expires}
}
