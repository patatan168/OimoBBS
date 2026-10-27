// 通常の送信権限検査が更新用mutexを待たず、失効とCloseを即座に検出することを検査する。
package app

import (
	"testing"
	"time"
)

func TestPublicLeaseCheckDoesNotWaitForPublicationUpdate(t *testing.T) {
	g := &publicationGate{leases: map[*PublicLease]func(){}}
	s := &PostingSnapshot{gate: g, Expires: 100}
	lease, err := s.AcquirePublic(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- lease.Check(2) }()
	select {
	case err := <-done:
		g.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		g.mu.Unlock()
		<-done
		lease.Close()
		t.Fatal("lease check waited for writer mutex")
	}
	lease.Close()
	if lease.Check(2) == nil {
		t.Fatal("closed lease remained valid")
	}
}
