// 別IPの小応答が続いても、全文の送信片へ帯域補充を残すことを検査する。
package delivery

import (
	"net/netip"
	"testing"
	"time"
)

func TestBudgetAcrossIPsCannotStarveBulk(t *testing.T) {
	now := time.Now()
	bulkIP := netip.MustParseAddr("192.0.2.1")
	smallIP := netip.MustParseAddr("192.0.2.2")
	bulk := &request{size: Chunk, ready: make(chan *Permit, 1)}
	s := &Scheduler{subjects: map[netip.Addr]*subject{bulkIP: {queue: []*request{bulk}}, smallIP: {}}, order: []netip.Addr{bulkIP, smallIP}, queued: 1, rate: 80000000, last: now, wake: make(chan struct{}, 1)}
	for i := 0; i < 50 && bulk.permit == nil; i++ {
		small := &request{size: 512, ready: make(chan *Permit, 1)}
		s.subjects[smallIP].queue = append(s.subjects[smallIP].queue, small)
		s.queued++
		now = now.Add(512 * 8 * time.Second / 80000000)
		s.pumpLocked(now)
		// 送信済み枠を戻すが、試験中は両主体を巡回から除去しない。
		for _, sub := range s.subjects {
			sub.active = 0
		}
	}
	if bulk.permit == nil {
		t.Fatal("別IPの小予約が大予約を無期限に追い越した")
	}
	if s.budgetHead == bulk {
		t.Fatal("送信済み予約を予算待ちとして保持した")
	}
}

func TestCancelBudgetHeadResumesOthers(t *testing.T) {
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	r := &request{size: Chunk, budgetBypasses: budgetBypassLimit, ready: make(chan *Permit, 1)}
	s := &Scheduler{subjects: map[netip.Addr]*subject{ip: {queue: []*request{r}}}, order: []netip.Addr{ip}, queued: 1, rate: 80000000, last: now, wake: make(chan struct{}, 1), budgetHead: r}
	s.cancel(ip, r)
	if s.budgetHead != nil || s.queued != 0 {
		t.Fatal("取消後に予算待ちを残した")
	}
}

func TestBudgetBypassAlsoBoundsBytes(t *testing.T) {
	now := time.Now()
	bulkIP, smallIP := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	bulk := &request{size: Chunk, ready: make(chan *Permit, 1)}
	small := &subject{}
	for range 3 {
		small.queue = append(small.queue, &request{size: Chunk / 2, ready: make(chan *Permit, 1)})
	}
	s := &Scheduler{subjects: map[netip.Addr]*subject{bulkIP: {queue: []*request{bulk}}, smallIP: small}, order: []netip.Addr{bulkIP, smallIP}, queued: 4, rate: 80000000, last: now, wake: make(chan struct{}, 1)}
	last := small.queue[2]
	for range 3 {
		s.tokens = uint64(Chunk/2) * 8 * uint64(time.Second)
		s.pumpLocked(now)
		small.active = 0
	}
	if last.permit != nil || bulk.budgetBypassBytes != Chunk {
		t.Fatal("大きい応答の追越しbyte量を制限しなかった")
	}
	s.tokens = uint64(Chunk) * 8 * uint64(time.Second)
	s.pumpLocked(now)
	if bulk.permit == nil {
		t.Fatal("追越し停止後に全文送信を再開しなかった")
	}
}

func TestBudgetHeadWithFullSocketSlotsDoesNotBlockOtherIPs(t *testing.T) {
	now := time.Now()
	busyIP, otherIP := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	head := &request{size: Chunk, budgetBypasses: budgetBypassLimit, ready: make(chan *Permit, 1)}
	other := &request{size: 512, ready: make(chan *Permit, 1)}
	s := &Scheduler{subjects: map[netip.Addr]*subject{busyIP: {active: 4, queue: []*request{head}}, otherIP: {queue: []*request{other}}}, order: []netip.Addr{busyIP, otherIP}, queued: 2, rate: 80000000, tokens: 512 * 8 * uint64(time.Second), last: now, wake: make(chan struct{}, 1), budgetHead: head, budgetIP: busyIP}
	s.pumpLocked(now)
	if other.permit == nil {
		t.Fatal("書込み中4枠の主体が別IPの送信を止めた")
	}
}
