// 取得済みsnapshotの失効・期限ラッチ・通知・リース解放を確認する。
package app

import (
	"oimobbs/internal/domain"
	"sync/atomic"
	"testing"
)

func TestPublicLeaseRevocation(t *testing.T) {
	gate := &publicationGate{leases: map[*PublicLease]func(){}}
	p := &PostingLog{gate: gate}
	snapshot := &PostingSnapshot{gate: gate, epoch: 0, Expires: 100}
	var revoked atomic.Int32
	lease, e := snapshot.AcquirePublic(1, func() { revoked.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	p.BlockPublic(true)
	if revoked.Load() != 1 || lease.Check(1) == nil {
		t.Fatal("old lease survived deletion")
	}
	p.BlockPublic(false)
	if _, e = snapshot.AcquirePublic(1, nil); e == nil {
		t.Fatal("old snapshot reacquired lease")
	}
	fresh := &PostingSnapshot{gate: gate, epoch: gate.epoch, Expires: 100}
	lease, e = fresh.AcquirePublic(1, func() { revoked.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	if lease.Check(100) == nil || revoked.Load() != 2 {
		t.Fatal("expiry did not revoke")
	}
	if _, e = fresh.AcquirePublic(domain.Time(2), nil); e == nil {
		t.Fatal("clock rollback revived publication")
	}
	lease.Close()
	lease.Close()
	if len(gate.leases) != 0 {
		t.Fatal("leaked lease")
	}
}

func TestPublicLeaseCloseSuppressesCallback(t *testing.T) {
	gate := &publicationGate{leases: map[*PublicLease]func(){}}
	snapshot := &PostingSnapshot{gate: gate, Expires: 100}
	called := false
	lease, e := snapshot.AcquirePublic(1, func() { called = true })
	if e != nil {
		t.Fatal(e)
	}
	lease.Close()
	p := &PostingLog{gate: gate}
	p.BlockPublic(true)
	if called || lease.Check(1) == nil {
		t.Fatal("closed lease notification")
	}
}

func TestAcquireAtExpiryRevokesAndLatches(t *testing.T) {
	gate := &publicationGate{leases: map[*PublicLease]func(){}}
	snapshot := &PostingSnapshot{gate: gate, Expires: 100}
	var revoked atomic.Int32
	lease, e := snapshot.AcquirePublic(1, func() { revoked.Add(1) })
	if e != nil {
		t.Fatal(e)
	}
	if _, e := snapshot.AcquirePublic(100, nil); e == nil || revoked.Load() != 1 {
		t.Fatal("acquisition did not latch expiry", e)
	}
	if lease.Check(2) == nil {
		t.Fatal("clock rollback revived old lease")
	}
	if _, e := snapshot.AcquirePublic(2, nil); e == nil {
		t.Fatal("clock rollback revived acquisition")
	}
}
