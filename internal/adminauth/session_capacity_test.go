// アカウント別のセッション上限、最終利用順の失効と他アカウントの分離を検証する。
package adminauth

import (
	"errors"
	"oimobbs/internal/domain"
	"sync"
	"testing"
	"time"
)

func TestSessionAccountCapacity(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	owner, other := domain.NewID(), domain.NewID()
	otherRaw, _, err := m.Create(other, 1, now)
	if err != nil {
		t.Fatal(err)
	}
	raws := make([]string, 32)
	snapshots := make([]Session, 32)
	for i := range raws {
		raws[i], snapshots[i], err = m.Create(owner, 1, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
	}
	// 最古のセッションを利用すると、次に古い未使用セッションが失効対象になる。
	if _, err = m.Lookup(raws[0], now.Add(40*time.Second)); err != nil {
		t.Fatal(err)
	}
	newRaw, _, err := m.Create(owner, 1, now.Add(41*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Lookup(raws[1], now.Add(41*time.Second)); !errors.Is(err, ErrSession) {
		t.Fatal("least recently used session retained", err)
	}
	if err = m.Check(snapshots[1], now.Add(41*time.Second)); !errors.Is(err, ErrSession) {
		t.Fatal("evicted in-flight session accepted", err)
	}
	for _, raw := range []string{raws[0], raws[31], otherRaw, newRaw} {
		if _, err = m.Lookup(raw, now.Add(41*time.Second)); err != nil {
			t.Fatal("unrelated or active session evicted", err)
		}
	}
	if len(m.sessions) != 33 {
		t.Fatal("account capacity", len(m.sessions))
	}
}

func TestSessionConcurrentAccountCapacity(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	owner := domain.NewID()
	var wg sync.WaitGroup
	for range 128 {
		wg.Go(func() {
			if _, _, err := m.Create(owner, 1, now); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if len(m.sessions) != 32 {
		t.Fatal("concurrent capacity", len(m.sessions))
	}
	if _, _, err = m.Create(domain.NewID(), 1, now); err != nil {
		t.Fatal("another account blocked", err)
	}
}

// TestSessionGlobalCapacity は全体枠が満杯でも自分の32件内で更新できることを確認する。
func TestSessionGlobalCapacity(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	owner := domain.NewID()
	var raw string
	var session Session
	for range 32 {
		raw, session, err = m.Create(owner, 1, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	// 他アカウントが保持する実在のセッションを複製せず、別handleで全体上限を構成する。
	for i := 32; i < 10000; i++ {
		h := [32]byte{byte(i), byte(i >> 8), byte(i >> 16)}
		m.sessions[h] = Session{Admin: domain.NewID(), Generation: 1, created: now, last: now, handle: h}
	}
	if _, _, err = m.Create(domain.NewID(), 1, now); !errors.Is(err, ErrBusy) {
		t.Fatal("global capacity lost", err)
	}
	if len(m.sessions) != 10000 {
		t.Fatal("failed create changed capacity")
	}
	// Cookieの更新だけでは上限判定・失効処理を行わず、件数も増えない。
	if _, _, err = m.MarkReauthenticated(raw, session, now); err != nil {
		t.Fatal("rotation rejected", err)
	}
	if _, _, err = m.Create(owner, 1, now); err != nil {
		t.Fatal("own replacement rejected at global cap", err)
	}
	if len(m.sessions) != 10000 {
		t.Fatal("replacement changed global capacity", len(m.sessions))
	}
}
