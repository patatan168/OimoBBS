// 複数主体の投稿枠を一つのmutexで予約し、確定・返却・不明の状態を管理する。
package abuse

import (
	"errors"
	"math/bits"
	"sync"
	"time"
)

var (
	ErrRateTicket    = errors.New("invalid rate ticket transition")
	ErrRateCapacity  = errors.New("rate key capacity exhausted")
	ErrRateClock     = errors.New("rate clock reversed")
	ErrRateUncertain = errors.New("rate reservations unresolved")
	ErrRateSpec      = errors.New("invalid rate specification")
)

// RateLimited は公開してよい待ち秒だけを返し、主体キーを含めない。
type RateLimited struct{ RetryAfter uint64 }

func (e *RateLimited) Error() string { return "posting rate exceeded" }

// RateSpec はEveryあたりTokensを補充する条件。変更はReconfigureを経由する。長期窓は現在分＋過去60分。
// creditはEveryのナノ秒を1tokenの単位とし、端数の補充を整数で保持する。
type RateSpec struct {
	Tokens                uint64
	Every                 time.Duration
	Burst, WindowLimit    uint32
	Disabled, TrackWindow bool
}

// RateCharge は一つの主体キーに対する消費。キーは上位層でHMAC化する。
type RateCharge struct {
	Key  string
	Spec RateSpec
	Cost uint32
}
type rateMinute struct {
	minute int64
	count  uint64
}
type rateBucket struct {
	spec    RateSpec
	credit  uint64
	last    time.Time
	minutes *[61]rateMinute
	pending uint64
}

// RateTicket は所有制限器以外から完了できない一回限りの予約。
type RateTicket struct {
	owner   *Limiter
	charges []RateCharge
	debits  []uint64
	at      time.Time
	state   uint8
}

// Limiter はサイト全体で共有する。mutex中にI/Oやワーカーの呼戻しを行わない。
type Limiter struct {
	mu    sync.Mutex
	limit int
	keys  map[string]*rateBucket
}

// NewLimiter は上限付き制限器を生成する。不正上限ではすべての新規キーを拒否する。
func NewLimiter(limit int) *Limiter {
	return &Limiter{limit: limit, keys: make(map[string]*rateBucket)}
}
func (s RateSpec) valid() bool {
	if s.Tokens == 0 || s.Tokens > 1000000000 || s.Every <= 0 || s.Every > time.Hour || s.Burst == 0 || s.Burst > 1000000 {
		return false
	}
	capacity := uint64(s.Burst) * uint64(s.Every)
	return ceilRate(capacity, s.Tokens) <= uint64(time.Hour)
}
func ceilRate(n, d uint64) uint64 { return n/d + boolRate(n%d != 0) }
func boolRate(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
func (b *rateBucket) capacity() uint64 { return uint64(b.spec.Burst) * uint64(b.spec.Every) }
func (b *rateBucket) refill(now time.Time) error {
	if now.Before(b.last) || now.UnixNano() < b.last.UnixNano() {
		return ErrRateClock
	}
	elapsed := uint64(now.Sub(b.last))
	missing := b.capacity() - b.credit
	if elapsed >= ceilRate(missing, b.spec.Tokens) {
		b.credit = b.capacity()
	} else {
		b.credit += elapsed * b.spec.Tokens
	}
	b.last = now
	return nil
}
func (b *rateBucket) count(minute int64) uint64 {
	count := b.pending
	if b.minutes == nil {
		return count
	}
	for _, v := range b.minutes {
		if v.minute >= minute-60 && v.minute <= minute {
			count += v.count
		}
	}
	return count
}
func (b *rateBucket) wait(now time.Time, cost uint32) (uint64, error) {
	debit := uint64(cost) * uint64(b.spec.Every)
	wait := uint64(0)
	if b.credit < debit {
		wait = ceilRate(ceilRate(debit-b.credit, b.spec.Tokens), uint64(time.Second))
	}
	if b.spec.WindowLimit == 0 {
		return wait, nil
	}
	if uint64(cost)+b.pending > uint64(b.spec.WindowLimit) {
		return 0, ErrRateUncertain
	}
	minute := now.Unix() / 60
	for offset := int64(0); offset <= 61; offset++ {
		if b.count(minute+offset)+uint64(cost) <= uint64(b.spec.WindowLimit) {
			if offset > 0 {
				seconds := uint64((minute+offset)*60 - now.Unix())
				wait = max(wait, seconds)
			}
			return wait, nil
		}
	}
	return 0, ErrRateUncertain
}

// Reserve は全キーを試算後、一括して消費する。不足・上限時に一部だけ予約しない。
func (l *Limiter) Reserve(now time.Time, charges []RateCharge) (*RateTicket, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(charges) == 0 || len(charges) > 16 || now.Unix() < 0 {
		return nil, ErrRateSpec
	}
	seen := map[string]bool{}
	newCount := 0
	for _, c := range charges {
		if c.Key == "" || len(c.Key) > 256 || seen[c.Key] || !c.Spec.valid() || c.Cost == 0 || c.Cost > c.Spec.Burst || c.Spec.WindowLimit > 0 && c.Cost > c.Spec.WindowLimit {
			return nil, ErrRateSpec
		}
		seen[c.Key] = true
		if b := l.keys[c.Key]; b != nil {
			if b.spec != c.Spec {
				return nil, ErrRateSpec
			}
			if now.Before(b.last) || now.UnixNano() < b.last.UnixNano() {
				return nil, ErrRateClock
			}
		} else {
			newCount++
		}
	}
	if len(l.keys)+newCount > l.limit {
		// 定期回収の位相や復旧開始時刻により、回収可能キーが容量拒否を起こさないよう再試算する。
		l.pruneLocked(now)
		newCount = 0
		for _, c := range charges {
			if l.keys[c.Key] == nil {
				newCount++
			}
		}
		if len(l.keys)+newCount > l.limit {
			return nil, ErrRateCapacity
		}
	}
	candidates := make([]*rateBucket, len(charges))
	wait := uint64(0)
	for i, c := range charges {
		b := l.keys[c.Key]
		if b == nil {
			b = &rateBucket{spec: c.Spec, last: now}
			b.credit = b.capacity()
			if b.spec.WindowLimit > 0 || b.spec.TrackWindow {
				b.minutes = new([61]rateMinute)
			}
		}
		if e := b.refill(now); e != nil {
			return nil, e
		}
		w, e := uint64(0), error(nil)
		if !b.spec.Disabled {
			w, e = b.wait(now, c.Cost)
		}
		if e != nil {
			return nil, e
		}
		wait = max(wait, w)
		candidates[i] = b
	}
	if wait > 0 {
		return nil, &RateLimited{RetryAfter: wait}
	}
	debits := make([]uint64, len(charges))
	for i, c := range charges {
		b := candidates[i]
		debits[i] = min(b.credit, uint64(c.Cost)*uint64(c.Spec.Every))
		b.credit -= debits[i]
		b.pending += uint64(c.Cost)
		l.keys[c.Key] = b
	}
	return &RateTicket{owner: l, charges: append([]RateCharge(nil), charges...), debits: debits, at: now}, nil
}

// Commit は永続受理後に保留件数を確定履歴へ移す。
func (l *Limiter) Commit(t *RateTicket) error { return l.finish(t, 1) }

// Release は未保存と確定した予約だけを返却する。
func (l *Limiter) Release(t *RateTicket) error { return l.finish(t, 2) }

// Uncertain は保存不明の予約を返却せず、復旧照合まで残す。
func (l *Limiter) Uncertain(t *RateTicket) error { return l.finish(t, 3) }
func (l *Limiter) finish(t *RateTicket, state uint8) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t == nil || t.owner != l || t.state != 0 {
		return ErrRateTicket
	}
	t.state = state
	if state == 3 {
		return nil
	}
	for i, c := range t.charges {
		b := l.keys[c.Key]
		b.pending -= uint64(c.Cost)
		if state == 2 {
			b.credit = min(b.capacity(), b.credit+t.debits[i])
			continue
		}
		if b.spec.WindowLimit > 0 || b.spec.TrackWindow {
			minute := t.at.Unix() / 60
			v := &b.minutes[minute%61]
			if v.minute > minute {
				continue
			}
			if v.minute != minute {
				*v = rateMinute{minute: minute}
			}
			v.count += uint64(c.Cost)
		}
	}
	return nil
}

// Prune は履歴・保留が不要で満補充のキーだけを回収する。未解決予約は回収しない。
func (l *Limiter) Prune(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.pruneLocked(now)
}
func (l *Limiter) pruneLocked(now time.Time) {
	for key, b := range l.keys {
		if b.refill(now) == nil && b.pending == 0 && b.credit == b.capacity() && b.count(now.Unix()/60) == 0 {
			delete(l.keys, key)
		}
	}
}

// Reconfigure は未解決予約のないキーだけを変更し、消費済みtoken数と61分履歴を引き継ぐ。
// burstを減らした場合の消費量は新しい容量で飽和する。キーと履歴を作り直さない。
func (l *Limiter) Reconfigure(now time.Time, specs map[string]RateSpec) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, spec := range specs {
		if !spec.valid() {
			return ErrRateSpec
		}
		if b := l.keys[key]; b != nil {
			if b.pending != 0 {
				return ErrRateUncertain
			}
			if now.Before(b.last) {
				return ErrRateClock
			}
		}
	}
	for key, spec := range specs {
		b := l.keys[key]
		if b == nil {
			continue
		}
		if e := b.refill(now); e != nil {
			return e
		}
		// 不足分の単位を新しいEveryへ換算する。切上げにより消費を少なく見積もらない。
		used := b.capacity() - b.credit
		whole, rem := used/uint64(b.spec.Every), used%uint64(b.spec.Every)
		hi, lo := bits.Mul64(rem, uint64(spec.Every))
		frac, remainder := bits.Div64(hi, lo, uint64(b.spec.Every))
		deficit := whole*uint64(spec.Every) + frac + boolRate(remainder != 0)
		b.spec = spec
		b.credit = b.capacity() - min(b.capacity(), deficit)
		if (spec.TrackWindow || spec.WindowLimit > 0) && b.minutes == nil {
			b.minutes = new([61]rateMinute)
		}
	}
	return nil
}

// RetainKeys は回収済みキーへの追跡参照を除く。制限器の消費状態は変更しない。
func (l *Limiter) RetainKeys(keys map[string]bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for key := range keys {
		if l.keys[key] == nil {
			delete(keys, key)
		}
	}
}
