// ログイン画面の大量発行で正規フォームが失効せず、使用済み記録が有限になることを検証する。
package adminauth

import (
	"errors"
	"testing"
	"time"
)

func TestLoginFormIssuanceDoesNotReserveCapacity(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	first, csrf, err := m.LoginForm(now)
	if err != nil {
		t.Fatal(err)
	}
	for range 20000 {
		if _, _, err = m.LoginForm(now); err != nil {
			t.Fatal("anonymous page requests exhausted capacity", err)
		}
	}
	if len(m.nonces) != 0 {
		t.Fatal("page issuance retained server state")
	}
	if err = m.ConsumeLogin(first, csrf, now); err != nil {
		t.Fatal("earlier genuine form unavailable", err)
	}
	if err = m.ConsumeLogin(first, csrf, now); !errors.Is(err, ErrSession) {
		t.Fatal("replay accepted", err)
	}
}

func TestLoginFormSignatureExpiryAndProcessBinding(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	raw, csrf, err := m.LoginForm(now)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range []time.Time{now.Add(-time.Nanosecond), now.Add(10 * time.Minute)} {
		if err = m.ConsumeLogin(raw, csrf, at); !errors.Is(err, ErrSession) {
			t.Fatal("future or expired form accepted", err)
		}
	}
	if err = m.ConsumeLogin(raw, "forged", now); !errors.Is(err, ErrSession) {
		t.Fatal("forged signature accepted")
	}
	other, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if err = other.ConsumeLogin(raw, csrf, now); !errors.Is(err, ErrSession) {
		t.Fatal("old process form accepted")
	}
	if len(m.nonces) != 0 || len(m.attempts) != 0 {
		t.Fatal("invalid requests allocated state")
	}
	if err = m.ConsumeLogin(raw, csrf, now.Add(9*time.Minute)); err != nil {
		t.Fatal("valid original form lost", err)
	}
}

func TestLoginFormSourceLimitDoesNotReserveGlobalUse(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1800000000, 0)
	for i := 0; i < 32; i++ {
		now := start.Add(time.Duration(i/2) * time.Second)
		raw, csrf, err := m.LoginForm(now)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.ConsumeLoginFrom(raw, csrf, "source-a", now); err != nil {
			t.Fatal(i, err)
		}
	}
	now := start.Add(16 * time.Second)
	raw, csrf, err := m.LoginForm(now)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.ConsumeLoginFrom(raw, csrf, "source-a", now); err == nil {
		t.Fatal("source limit absent")
	}
	if err = m.ConsumeLoginFrom(raw, csrf, "source-b", now); err != nil {
		t.Fatal("rejected source consumed token or unrelated source blocked", err)
	}
}

func TestLoginFormConsumptionRemainsBoundedWithoutEvictingReplayRecords(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(1800000000, 0)
	var last, csrf string
	for second := 0; second <= 600; second++ {
		now := start.Add(time.Duration(second) * time.Second)
		for range 16 {
			last, csrf, err = m.LoginForm(now)
			if err != nil {
				t.Fatal(err)
			}
			if err = m.ConsumeLogin(last, csrf, now); err != nil {
				t.Fatal(second, err)
			}
		}
		if len(m.nonces) > 9600 {
			t.Fatal("unbounded spent tokens", len(m.nonces))
		}
		extra, signature, err := m.LoginForm(now)
		if err != nil {
			t.Fatal(err)
		}
		if err = m.ConsumeLogin(extra, signature, now); err == nil {
			t.Fatal("global consumption rate absent")
		}
	}
	if err = m.ConsumeLogin(last, csrf, start.Add(601*time.Second)); !errors.Is(err, ErrSession) {
		t.Fatal("recent replay record evicted", err)
	}
}
