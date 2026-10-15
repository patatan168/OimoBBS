// 導出・nonce再利用・経路別CSRF・期限・複数試行枠を注入時刻で検証する。
package adminauth

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

const testPassword = "local-admin-test-password-only"

func TestPasswordAndSession(t *testing.T) {
	p, e := NewPassword(testPassword)
	if e != nil {
		t.Fatal(e)
	}
	if !p.Verify(testPassword) || p.Verify("incorrect password") {
		t.Fatal("password verification")
	}
	p2, e := NewPassword(testPassword)
	if e != nil || p2.Salt == p.Salt {
		t.Fatal("salt reused")
	}
	if _, e = NewPassword("short"); e == nil {
		t.Fatal("short secret accepted")
	}
	m, e := New()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	nonce, csrf, e := m.LoginForm(now)
	if e != nil {
		t.Fatal(e)
	}
	if m.ConsumeLogin(nonce, "wrong", now) == nil {
		t.Fatal("forged CSRF")
	}
	if e = m.ConsumeLogin(nonce, csrf, now); e != nil {
		t.Fatal(e)
	}
	if m.ConsumeLogin(nonce, csrf, now) == nil {
		t.Fatal("nonce replay")
	}
	if ok, e := m.Verify(context.Background(), nil, testPassword); e != nil || ok {
		t.Fatal("dummy accepted")
	}
	raw, s, e := m.Create(domain.NewID(), 1, now)
	if e != nil {
		t.Fatal(e)
	}
	if !s.CheckCSRF("/site", s.CSRF("/site")) || s.CheckCSRF("/logout", s.CSRF("/site")) {
		t.Fatal("CSRF path binding")
	}
	if _, e = m.Lookup(raw, now.Add(30*time.Minute)); !errors.Is(e, ErrSession) {
		t.Fatal("idle expiration")
	}
	raw, _, e = m.Create(domain.NewID(), 1, now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i < 48; i++ {
		if _, e = m.Lookup(raw, now.Add(time.Duration(i)*10*time.Minute)); e != nil {
			t.Fatal("active session expired", i)
		}
	}
	if _, e = m.Lookup(raw, now.Add(8*time.Hour)); !errors.Is(e, ErrSession) {
		t.Fatal("absolute expiration")
	}
	raw, _, e = m.Create(domain.NewID(), 1, now)
	if e != nil {
		t.Fatal(e)
	}
	m.Delete(raw)
	if _, e = m.Lookup(raw, now); e == nil {
		t.Fatal("logout retained session")
	}
}
func TestLoginAttemptAtomic(t *testing.T) {
	m, e := New()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	for range 5 {
		if e = m.Attempt("ip-a", "account-a", now); e != nil {
			t.Fatal(e)
		}
	}
	var limited *Limited
	if e = m.Attempt("ip-b", "account-a", now); !errors.As(e, &limited) || limited.RetryAfter != 60 {
		t.Fatal("account cap", e)
	}
	for range 5 {
		if e = m.Attempt("ip-b", "account-b", now); e != nil {
			t.Fatal("failed request consumed IP", e)
		}
	}
	if e = m.Attempt("ip-a", "account-c", now); !errors.As(e, &limited) {
		t.Fatal("IP cap", e)
	}
	if e = m.Attempt("ip-a", "account-a", now.Add(time.Minute)); e != nil {
		t.Fatal("minute expiry", e)
	}
}
func BenchmarkPasswordVerify(b *testing.B) {
	p, e := NewPassword(testPassword)
	if e != nil {
		b.Fatal(e)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !p.Verify(testPassword) {
			b.Fatal("verify")
		}
	}
}

// TestExplicitReauthentication は境界・時計後退・失効した認証中セッションを検査する。
func TestExplicitReauthentication(t *testing.T) {
	m, e := New()
	if e != nil {
		t.Fatal(e)
	}
	now := time.Unix(1800000000, 0)
	raw, s, e := m.Create(domain.NewID(), 1, now)
	if e != nil {
		t.Fatal(e)
	}
	if s.Reauthenticated(now) {
		t.Fatal("login implicitly reauthenticated")
	}
	next, fresh, e := m.MarkReauthenticated(raw, s, now.Add(time.Minute))
	if e != nil {
		t.Fatal(e)
	}
	if !fresh.Reauthenticated(now.Add(time.Minute)) || !fresh.Reauthenticated(now.Add(6*time.Minute)) || !fresh.Reauthenticated(now.Add(11*time.Minute-time.Nanosecond)) || fresh.Reauthenticated(now.Add(11*time.Minute)) || fresh.Reauthenticated(now) {
		t.Fatal("freshness boundary")
	}
	if _, e = m.Lookup(raw, now.Add(time.Minute)); e == nil {
		t.Fatal("old cookie retained")
	}
	if fresh.CheckCSRF("/site", s.CSRF("/site")) {
		t.Fatal("old csrf retained")
	}
	raw, s = next, fresh
	found, e := m.Lookup(raw, now.Add(2*time.Minute))
	if e != nil || !found.Reauthenticated(now.Add(2*time.Minute)) {
		t.Fatal("freshness not saved")
	}
	if _, _, e = m.MarkReauthenticated(raw, s, now.Add(time.Minute)); e == nil {
		t.Fatal("rollback accepted")
	}
	changed := s
	changed.Generation++
	if _, _, e = m.MarkReauthenticated(raw, changed, now.Add(3*time.Minute)); e == nil {
		t.Fatal("generation mismatch")
	}
	m.Delete(raw)
	if _, _, e = m.MarkReauthenticated(raw, s, now.Add(3*time.Minute)); e == nil {
		t.Fatal("logout resurrected")
	}
	raw, s, e = m.Create(domain.NewID(), 1, now)
	if e != nil {
		t.Fatal(e)
	}
	for i := 1; i < 48; i++ {
		s, e = m.Lookup(raw, now.Add(time.Duration(i)*10*time.Minute))
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, _, e = m.MarkReauthenticated(raw, s, now.Add(8*time.Hour)); e == nil {
		t.Fatal("reauth extended absolute deadline")
	}
}

// TestCheckQueuedSession は待機済みのセッション写しを失効後に再利用できないことを検査する。
func TestCheckQueuedSession(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	raw, s, err := m.Create(domain.NewID(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Check(s, now); err != nil {
		t.Fatal(err)
	}
	if err = m.Check(s, now.Add(30*time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("idle expiry", err)
	}
	// 照合だけでは無操作期限を延ばさない。
	if err = m.Check(s, now.Add(29*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Lookup(raw, now.Add(30*time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("check refreshed idle expiry", err)
	}
	raw, s, err = m.Create(domain.NewID(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	next, fresh, err := m.MarkReauthenticated(raw, s, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Check(s, now.Add(time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("rotated copy survived", err)
	}
	if err = m.Check(fresh, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	m.Delete(next)
	if err = m.Check(fresh, now.Add(time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("logged out copy survived", err)
	}
	if err = m.Check(Session{Admin: fresh.Admin, Generation: fresh.Generation}, now); !errors.Is(err, ErrSession) {
		t.Fatal("unissued session accepted", err)
	}
}

// TestCheckCurrentLifetime は写しの古いlastでなく現在の無操作期限と元の絶対期限を照合する。
func TestCheckCurrentLifetime(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	raw, s, err := m.Create(domain.NewID(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 48; i++ {
		at := now.Add(time.Duration(i) * 10 * time.Minute)
		if _, err = m.Lookup(raw, at); err != nil {
			t.Fatal(err)
		}
		if err = m.Check(s, at); err != nil {
			t.Fatal("active session copy expired", err)
		}
	}
	if err = m.Check(s, now.Add(8*time.Hour)); !errors.Is(err, ErrSession) {
		t.Fatal("absolute expiry", err)
	}
	if err = m.Check(s, now.Add(time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("clock rollback", err)
	}
	s.Generation++
	if err = m.Check(s, now.Add(470*time.Minute)); !errors.Is(err, ErrSession) {
		t.Fatal("generation changed", err)
	}
}
