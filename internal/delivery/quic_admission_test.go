// QUICの接続元枠がIPv6 /64を共有し、取消時に解放されることを検査する。
package delivery

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestQUICAdmissionLifetimeAndIPv6(t *testing.T) {
	g, err := NewQUICAdmission(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	a := &net.UDPAddr{IP: net.ParseIP("2001:db8:1::1"), Port: 443}
	b := &net.UDPAddr{IP: net.ParseIP("2001:db8:1::2"), Port: 443}
	ctx, cancel := context.WithCancel(t.Context())
	if err = g.Admit(ctx, a); err != nil {
		t.Fatal(err)
	}
	if g.Admit(t.Context(), b) == nil {
		t.Fatal("IPv6 /64 cap bypassed")
	}
	cancel()
	deadline := time.Now().Add(time.Second)
	for {
		g.mu.Lock()
		n := g.total
		g.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel did not release")
		}
		runtime.Gosched()
	}
	if err = g.Admit(t.Context(), b); err != nil {
		t.Fatal(err)
	}
	if g.Admit(ctx, a) == nil {
		t.Fatal("cancelled connection admitted")
	}
}

// 未検証入力の枠はIPv6 /64で共有し、TLS admissionと既存接続の枠を消費しない。
func TestQUICUnvalidatedRateIsolation(t *testing.T) {
	g, err := NewQUICAdmission(4, 2)
	if err != nil {
		t.Fatal(err)
	}
	// 長時間の停止でも補充されない時刻を指定し、sleepに依存せず枠を使い切る。
	now := time.Now().Add(time.Hour)
	g.unvalidated.policy = ConnectionRate{GlobalRate: 1, GlobalBurst: 3, SourceRate: 1, SourceBurst: 2}
	g.unvalidated.global = connectionBucket{tokens: 3, at: now}
	a := &net.UDPAddr{IP: net.ParseIP("2001:db8:1::1"), Port: 443}
	b := &net.UDPAddr{IP: net.ParseIP("2001:db8:1::2"), Port: 444}
	c := &net.UDPAddr{IP: net.ParseIP("2001:db8:2::1"), Port: 443}
	if !g.AllowUnvalidated(a) || !g.AllowUnvalidated(b) || g.AllowUnvalidated(a) || !g.AllowUnvalidated(c) {
		t.Fatal("unvalidated source limit bypassed")
	}
	if g.AllowUnvalidated(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}) || g.AllowUnvalidated(nil) {
		t.Fatal("unvalidated global/address limit bypassed")
	}
	if err := g.Admit(t.Context(), a); err != nil {
		t.Fatal("unvalidated flood consumed verified admission", err)
	}
	if len(g.unvalidated.sources) != 2 {
		t.Fatal("rejected source retained", len(g.unvalidated.sources))
	}
}
