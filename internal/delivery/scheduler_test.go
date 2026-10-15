// 帯域補充・主体公平性・取消・枠返却を確定時刻と実要求で検査する。
package delivery

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestSchedulerRoundRobinAndActiveLimit(t *testing.T) {
	now := time.Now()
	// 12送信片を一巡で収める帯域にし、token不足と主体別4枠の検査を分ける。
	s := &Scheduler{subjects: map[netip.Addr]*subject{}, rate: 1000000000, tokens: burstBytes(1000000000) * 8 * uint64(time.Second), last: now, wake: make(chan struct{}, 1)}
	for _, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		ip := netip.MustParseAddr(raw)
		sub := &subject{}
		for i := 0; i < 5; i++ {
			sub.queue = append(sub.queue, &request{size: Chunk, ready: make(chan *Permit, 1)})
		}
		s.subjects[ip] = sub
		s.order = append(s.order, ip)
		s.queued += 5
	}
	s.mu.Lock()
	s.pumpLocked(now)
	s.mu.Unlock()
	queued, subjects, active := s.Stats()
	if queued != 3 || subjects != 3 || active != 12 {
		t.Fatal(queued, subjects, active)
	}
	for _, sub := range s.subjects {
		if sub.active != 4 || len(sub.queue) != 1 {
			t.Fatal("one IP monopolized grants")
		}
	}
	// 小量の主体へ切り替えた際にもcreditが無制限に増えない。
	for i := 0; i < 100; i++ {
		s.mu.Lock()
		s.pumpLocked(now)
		s.mu.Unlock()
	}
	for _, sub := range s.subjects {
		if sub.credit > creditLimit {
			t.Fatal("unbounded idle credit")
		}
	}
}

func TestSchedulerKeepsTurnAfterBudgetExhaustion(t *testing.T) {
	now := time.Now()
	s := &Scheduler{subjects: map[netip.Addr]*subject{}, rate: 80000000, last: now, wake: make(chan struct{}, 1)}
	for _, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		ip := netip.MustParseAddr(raw)
		sub := &subject{}
		for range 5 {
			sub.queue = append(sub.queue, &request{size: Chunk, ready: make(chan *Permit, 1)})
		}
		s.subjects[ip], s.order, s.queued = sub, append(s.order, ip), s.queued+5
	}
	for turn := range 6 {
		ip := s.order[turn%3]
		want := s.subjects[ip].queue[0]
		s.tokens = Chunk * 8 * uint64(time.Second)
		s.pumpLocked(now)
		if want.permit == nil {
			t.Fatalf("budget refill restarted at the same subject: turn %d", turn)
		}
		want.permit.Release()
	}
}

func TestDeliveryFixture(t *testing.T) {
	raw, e := os.ReadFile("../../docs/design/fixtures/runtime-cleanup-delivery.json")
	if e != nil {
		t.Fatal(e)
	}
	var root map[string]json.RawMessage
	if e = json.Unmarshal(raw, &root); e != nil {
		t.Fatal(e)
	}
	var config struct {
		Budget uint64 `json:"budget_bits_per_second"`
		Burst  int    `json:"burst_bytes"`
		Chunk  int    `json:"chunk_bytes"`
		Active int    `json:"subject_active_writes"`
		Queue  int    `json:"subject_queue"`
		Global int    `json:"global_queue"`
	}
	if e = json.Unmarshal(root["delivery"], &config); e != nil {
		t.Fatal(e)
	}
	if config.Burst != int(burstBytes(config.Budget)) || config.Chunk != Chunk || config.Active != 4 || config.Queue != 32 || config.Global != 4096 {
		t.Fatal("delivery fixture changed", config)
	}
	s, e := New(config.Budget)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if s.Status().Budget != config.Budget {
		t.Fatal("configured budget ignored")
	}
}

func TestSchedulerIntegerRefillAndClockRegression(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	r := &request{size: 1000, ready: make(chan *Permit, 1)}
	s := &Scheduler{subjects: map[netip.Addr]*subject{ip: {queue: []*request{r}}}, order: []netip.Addr{ip}, queued: 1, rate: 8000, last: now, wake: make(chan struct{}, 1)}
	s.pumpLocked(now.Add(-time.Hour))
	if r.permit != nil || s.last != now {
		t.Fatal("clock regression refilled tokens")
	}
	s.pumpLocked(now.Add(time.Second))
	if r.permit == nil || s.tokens != 0 {
		t.Fatal("bit budget or nanosecond arithmetic changed", s.tokens)
	}
	r.permit.Release()
	r.permit.Release()
	if q, n, a := s.Stats(); q != 0 || n != 0 || a != 0 {
		t.Fatal("permit not released exactly once", q, n, a)
	}
	s.pumpLocked(now.Add(10000 * time.Hour))
	if s.tokens != burstBytes(s.rate)*8*uint64(time.Second) {
		t.Fatal("long idle overflow", s.tokens)
	}
}

func TestSchedulerCancellationCapacityAndClose(t *testing.T) {
	s, e := New(1)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	s.mu.Lock()
	s.tokens = 0
	s.mu.Unlock()
	ip := netip.MustParseAddr("192.0.2.1")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { _, e := s.Reserve(ctx, ip, Chunk); result <- e }()
	deadline := time.Now().Add(time.Second)
	for {
		q, _, _ := s.Stats()
		if q == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request not queued")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if e := <-result; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if q, n, a := s.Stats(); q != 0 || n != 0 || a != 0 {
		t.Fatal("cancel retained inputs", q, n, a)
	}
	s.mu.Lock()
	s.queued = 4096
	s.mu.Unlock()
	if _, e := s.Reserve(context.Background(), ip, 1); !errors.Is(e, ErrCapacity) {
		t.Fatal(e)
	}
	s.mu.Lock()
	s.queued = 0
	s.mu.Unlock()
	go func() { _, e := s.Reserve(context.Background(), ip, Chunk); result <- e }()
	s.Close()
	if e := <-result; !errors.Is(e, ErrClosed) {
		t.Fatal(e)
	}
}
