// Package delivery はIP別の順番とサイト共通の送信量を、socket書込みの外側で予約する。
package delivery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Chunk は一回のヘッダ/本文予約と書込みの最大byte数。
const Chunk = 16 << 10
const burst = 1 << 20
const quantum = Chunk
const creditLimit = 4 * quantum

// budgetBypassLimit はIPをまたぐ追越し上限。小応答の進行と大予約の補充を両立する。
const budgetBypassLimit = 8

// DefaultBudgetBits は100Mbps回線で通信ヘッダ等の余裕を残す既定予算。
const DefaultBudgetBits uint64 = 80_000_000

// MaxBudgetBits は帯域拡張を含め運用者が指定できる最大送信予算。
const MaxBudgetBits uint64 = 100_000_000_000

// ErrCapacity は全体または主体の待機枠が満杯であることを示す。
var ErrCapacity = errors.New("delivery queue full")

// ErrClosed は終了済み送信枠への予約を示す。
var ErrClosed = errors.New("delivery scheduler closed")

type request struct {
	size              int
	bypasses          uint8
	ready             chan *Permit
	permit            *Permit
	budgetBypasses    uint8
	budgetBypassBytes int
}
type subject struct {
	queue          []*request
	credit, active int
}

// Scheduler は最大4096予約・主体32待機/4送信と帯域2ms分のburstを共有する。
// burstは32KiB〜1MiB。小予約の追越しは先頭あたり4回までとする。
// Closeで待機者を解放する。予約後の量は書込み失敗でも返却しない。
type Scheduler struct {
	mu               sync.Mutex
	subjects         map[netip.Addr]*subject
	order            []netip.Addr
	cursor, queued   int
	tokens, rate     uint64
	reservedBytes    uint64
	last             time.Time
	wake, stop, done chan struct{}
	closed           bool
	closedRead       atomic.Bool
	budgetHead       *request
	budgetIP         netip.Addr
}

// Permit は一送信片の枠。Releaseは書込み完了/取消時に一回だけ呼ぶ。
type Permit struct {
	scheduler *Scheduler
	ip        netip.Addr
	once      sync.Once
}

// New は1bit/s〜100Gbpsの明示予算を作る。要求/送信枠の上限は常に保つ。
func New(bits uint64) (*Scheduler, error) {
	if bits == 0 || bits > MaxBudgetBits {
		return nil, errors.New("invalid egress budget")
	}
	s := &Scheduler{subjects: map[netip.Addr]*subject{}, rate: bits, tokens: burstBytes(bits) * 8 * uint64(time.Second), last: schedulerNow(), wake: make(chan struct{}, 1), stop: make(chan struct{}), done: make(chan struct{})}
	go s.run()
	return s, nil
}

// Reserve はcanonical IPの有界queueへ登録し、取消またはtimeoutまでにDRR順で枠を返す。
// sizeは推定ヘッダまたは本文の1..16KiB。呼出元は最大250msのcontextを渡す。
func (s *Scheduler) Reserve(ctx context.Context, ip netip.Addr, size int) (*Permit, error) {
	return s.reserve(ctx, ip, size, Chunk)
}

// reserve は課金済みの量を有界queueへ登録し、枠の付与か取消を待つ。
// HTTP予約だけは通信分を加えた上限を使い、公開Reserveの上限は維持する。
func (s *Scheduler) reserve(ctx context.Context, ip netip.Addr, size, maximum int) (*Permit, error) {
	return s.reserveUntil(ctx, ip, size, maximum, time.Time{})
}

// reserveUntil は即時付与に通知channelやtimerを作らず、待つ場合だけ期限をcontextへ結ぶ。
// deadlineはmutexの取得前から数え、待機開始によってHTTPの250ms上限を延ばさない。
func (s *Scheduler) reserveUntil(ctx context.Context, ip netip.Addr, size, maximum int, deadline time.Time) (*Permit, error) {
	if !ip.IsValid() || ip.Zone() != "" || size < 1 || size > maximum {
		return nil, errors.New("invalid delivery reservation")
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !deadline.IsZero() && time.Until(deadline) <= 0 {
		return nil, context.DeadlineExceeded
	}
	ip = ip.Unmap()
	r := &request{size: size}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	sub := s.subjects[ip]
	if s.queued >= 4096 || sub != nil && len(sub.queue) >= 32 {
		s.mu.Unlock()
		return nil, ErrCapacity
	}
	if sub == nil {
		sub = &subject{}
		s.subjects[ip] = sub
		s.order = append(s.order, ip)
	}
	idle := s.queued == 0
	sub.queue = append(sub.queue, r)
	s.queued++
	// 待機者がなければ同じDRRと課金処理を直ちに行い、補充goroutineとの往復を省く。
	if idle {
		s.pumpLocked(schedulerNow())
	}
	p := r.permit
	if p == nil {
		// pumpLockedと同じmutex内で登録し、付与通知の取りこぼしを防ぐ。
		r.ready = make(chan *Permit, 1)
	}
	s.mu.Unlock()
	if p != nil {
		return s.acceptPermit(ctx, p, deadline)
	}
	s.signal()
	if !deadline.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	select {
	case p := <-r.ready:
		return s.acceptPermit(ctx, p, deadline)
	case <-ctx.Done():
		s.cancel(ip, r)
		return nil, ctx.Err()
	case <-s.stop:
		s.cancel(ip, r)
		return nil, ErrClosed
	}
}

// acceptPermit は即時/待機のどちらでも付与後の終了・取消・期限切れを検査し、枠を返す。
func (s *Scheduler) acceptPermit(ctx context.Context, p *Permit, deadline time.Time) (*Permit, error) {
	var err error
	if s.closedRead.Load() {
		err = ErrClosed
	} else if err = ctx.Err(); err == nil && !deadline.IsZero() && time.Until(deadline) <= 0 {
		err = context.DeadlineExceeded
	}
	if err != nil {
		p.Release()
		return nil, err
	}
	return p, nil
}

// cancel は未開始予約を除去し、同時に付与済みなら送信枠だけを戻す。
func (s *Scheduler) cancel(ip netip.Addr, r *request) {
	s.mu.Lock()
	if sub := s.subjects[ip]; sub != nil && r.permit == nil {
		for i, v := range sub.queue {
			if v == r {
				if s.budgetHead == r {
					s.budgetHead = nil
				}
				copy(sub.queue[i:], sub.queue[i+1:])
				sub.queue[len(sub.queue)-1] = nil
				sub.queue = sub.queue[:len(sub.queue)-1]
				s.queued--
				break
			}
		}
	}
	p := r.permit
	s.pruneLocked(ip)
	s.mu.Unlock()
	if p != nil {
		p.Release()
	}
	s.signal()
}

// Release は送信中の枠を返し、次の主体の待機を起こす。二重呼出しは無操作。
func (p *Permit) Release() {
	p.once.Do(func() {
		s := p.scheduler
		s.mu.Lock()
		if sub := s.subjects[p.ip]; sub != nil {
			sub.active--
		}
		s.pruneLocked(p.ip)
		// 送信完了で空いた枠は同じDRRで直ちに渡し、復旧時のgoroutine往復を省く。
		if s.queued > 0 {
			s.pumpLocked(schedulerNow())
		}
		waiting := s.queued > 0
		s.mu.Unlock()
		if waiting {
			s.signal()
		}
	})
}

// Close は新予約を停止し、待機者とtimerを解放する。送信済みの量は戻さない。
func (s *Scheduler) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.closedRead.Store(true)
		close(s.stop)
	}
	s.mu.Unlock()
	<-s.done
}

func (s *Scheduler) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// run は待機がある場合だけ10ms以下のtimerで補充し、mutexをsocketへ持ち込まない。
func (s *Scheduler) run() {
	defer close(s.done)
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		s.mu.Lock()
		s.pumpLocked(schedulerNow())
		waiting := s.queued > 0
		wait := s.refillWaitLocked()
		s.mu.Unlock()
		var tick <-chan time.Time
		if waiting {
			timer.Reset(wait)
			tick = timer.C
		}
		select {
		case <-s.stop:
			return
		case <-s.wake:
			if waiting && !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		case <-tick:
		}
	}
}

// refillWaitLocked は高速回線で10msごとの補充が上限にならないよう必要量から待つ。
func (s *Scheduler) refillWaitLocked() time.Duration {
	wait := 10 * time.Millisecond
	if s.rate == 0 {
		return wait
	}
	if head := s.budgetHead; head != nil && budgetHeld(head) {
		cost := uint64(head.size) * 8 * uint64(time.Second)
		if cost > s.tokens {
			return min(wait, max(100*time.Microsecond, time.Duration((cost-s.tokens+s.rate-1)/s.rate)))
		}
	}
	for _, sub := range s.subjects {
		if sub.active >= 4 || len(sub.queue) == 0 {
			continue
		}
		size := sub.queue[0].size
		if index := smallCandidate(sub); index > 0 {
			size = min(size, sub.queue[index].size)
		}
		cost := uint64(size) * 8 * uint64(time.Second)
		if cost > s.tokens {
			needed := time.Duration((cost - s.tokens + s.rate - 1) / s.rate)
			wait = min(wait, max(100*time.Microsecond, needed))
		}
	}
	return wait
}

// pumpLocked は整数bit-nsで補充し、各巡回の主体creditを64KiB以下に保つ。
func (s *Scheduler) pumpLocked(now time.Time) {
	if s.closed {
		return
	}
	// socket枠が埋まった主体のために全体の補充を止めない。
	if s.budgetHead != nil {
		if sub := s.subjects[s.budgetIP]; sub == nil || sub.active >= 4 {
			s.budgetHead = nil
		}
	}
	capacity := burstBytes(s.rate) * 8 * uint64(time.Second)
	if now.After(s.last) {
		elapsed := uint64(now.Sub(s.last))
		missing := capacity - s.tokens
		if elapsed >= (missing+s.rate-1)/s.rate {
			s.tokens = capacity
		} else {
			s.tokens += elapsed * s.rate
		}
		s.last = now
	}
	if head := s.budgetHead; head != nil && budgetHeld(head) && uint64(head.size)*8*uint64(time.Second) > s.tokens {
		return
	}
	// 4回転で全主体の最大4同時送信を進める。待機した主体は次のturnから始める。
	nextCursor := s.cursor
	for turns := 0; turns < len(s.order)*4 && s.queued > 0 && len(s.order) > 0; turns++ {
		s.cursor %= len(s.order)
		ip := s.order[s.cursor]
		s.cursor = (s.cursor + 1) % len(s.order)
		sub := s.subjects[ip]
		if len(sub.queue) == 0 || sub.active >= 4 {
			continue
		}
		sub.credit = min(creditLimit, sub.credit+quantum)
		index := 0
		if uint64(sub.queue[0].size)*8*uint64(time.Second) > s.tokens {
			index = smallCandidate(sub)
		}
		r := sub.queue[index]
		cost := uint64(r.size) * 8 * uint64(time.Second)
		// 別IPの小予約にも追越し上限を適用し、予算を待つ大予約の必要量を貯める。
		if s.budgetHead != nil && s.budgetHead != r && budgetHeld(s.budgetHead) {
			if uint64(s.budgetHead.size)*8*uint64(time.Second) > s.tokens {
				break
			}
			continue
		}
		if r.size > sub.credit || cost > s.tokens {
			if cost > s.tokens && r.size > 1024 && s.budgetHead == nil {
				s.budgetHead = r
				s.budgetIP = ip
			}
			continue
		}
		if s.budgetHead == r {
			s.budgetHead = nil
		} else if s.budgetHead != nil {
			s.budgetHead.budgetBypasses = min(budgetBypassLimit, s.budgetHead.budgetBypasses+1)
			s.budgetHead.budgetBypassBytes = min(s.budgetHead.size, s.budgetHead.budgetBypassBytes+r.size)
		}
		sub.credit -= r.size
		s.reservedBytes += uint64(r.size)
		s.tokens -= cost
		sub.active++
		if s.budgetHead != nil && ip == s.budgetIP && sub.active >= 4 {
			s.budgetHead = nil
		}
		s.queued--
		if index > 0 {
			sub.queue[0].bypasses++
		}
		copy(sub.queue[index:], sub.queue[index+1:])
		sub.queue[len(sub.queue)-1] = nil
		sub.queue = sub.queue[:len(sub.queue)-1]
		p := &Permit{scheduler: s, ip: ip}
		r.permit = p
		if r.ready != nil {
			r.ready <- p
		}
		nextCursor = s.cursor
	}
	// 予算不足の空巡回で先頭へ戻さず、最後に枠を渡した次の主体を維持する。
	s.cursor = nextCursor
}

// budgetHeld は8予約または待機先頭のbyte量に達したら補充を先頭へ残す。
// 件数だけでは小さいヘッダと大きい本文を同じ量として扱うため、byteでも制限する。
func budgetHeld(head *request) bool {
	return head.budgetBypasses >= budgetBypassLimit || head.budgetBypassBytes >= head.size
}

// burstBytes は2ms分だけを蓄積し、低帯域でも通信分付き最大送信片を通す。
func burstBytes(rate uint64) uint64 { return min(burst, max(2*Chunk, rate/4000)) }

// bodyChunk は待機が増えたとき送信片を縮め、全体の一巡を帯域50ms分以内へ近づける。
// 512byte〜16KiBの範囲で選び、帯域予算・要求数・送信中枠は増やさない。
func (s *Scheduler) bodyChunk() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return int(min(Chunk, max(512, s.rate/160/uint64(s.queued+1))))
}

// smallCandidate は小予約同士の順番を維持し、同じ先頭の追越しを4回に制限する。
func smallCandidate(sub *subject) int {
	if sub.queue[0].bypasses >= 4 {
		return 0
	}
	for i := 1; i < len(sub.queue); i++ {
		if sub.queue[i].size <= 1024 {
			return i
		}
	}
	return 0
}

// pruneLocked は解放した主体が空になった場合だけ巡回を縮め、creditを回収する。
func (s *Scheduler) pruneLocked(ip netip.Addr) {
	if sub := s.subjects[ip]; sub != nil && (len(sub.queue) > 0 || sub.active > 0) {
		return
	}
	if len(s.order) == 0 {
		return
	}
	// 空になった主体はこの呼出しのIPだけ。他主体のmap再走査は行わない。
	next := s.cursor % len(s.order)
	for index, entry := range s.order {
		if entry != ip {
			continue
		}
		delete(s.subjects, ip)
		copy(s.order[index:], s.order[index+1:])
		s.order[len(s.order)-1] = netip.Addr{}
		s.order = s.order[:len(s.order)-1]
		if index == next {
			next = 0
		} else if index < next {
			next--
		}
		s.cursor = next
		return
	}
}

// Stats は本文/IPを含めず、待機・稼働主体・送信枠の数だけを返す。
func (s *Scheduler) Stats() (queued, subjects, active int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sub := range s.subjects {
		active += sub.active
	}
	return s.queued, len(s.subjects), active
}

// Status は監視用の集計だけを返し、IP・本文・Cookieを含めない。
func (s *Scheduler) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := Status{Budget: s.rate, BurstBytes: burstBytes(s.rate), Queued: s.queued, Subjects: len(s.subjects), Reserved: s.reservedBytes}
	for _, sub := range s.subjects {
		result.Active += sub.active
	}
	return result
}

// Status は実送信/NIC量と区別した保守的な予約量と、現在の枠使用数。
type Status struct {
	Budget     uint64 `json:"budget_bits_per_second"`
	BurstBytes uint64 `json:"burst_bytes"`
	Queued     int    `json:"queued_chunks"`
	Subjects   int    `json:"active_subject_count"`
	Active     int    `json:"active_write_count"`
	Reserved   uint64 `json:"reserved_bytes"`
}

// UpdateBudget は既存の予約と送信枠を保って帯域を変更する。予算変更で新しいburstを付与しない。
func (s *Scheduler) UpdateBudget(bits uint64) error {
	if bits == 0 || bits > MaxBudgetBits {
		return errors.New("invalid egress budget")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	s.pumpLocked(schedulerNow())
	s.rate = bits
	s.tokens = min(s.tokens, burstBytes(bits)*8*uint64(time.Second))
	s.mu.Unlock()
	s.signal()
	return nil
}
