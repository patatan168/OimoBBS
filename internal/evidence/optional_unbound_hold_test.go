// 操作なし予約の原本保護・再読込・解除と、種別差替えの拒否を実保存先で検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/domain"
	"os"
	"testing"
	"time"
)

func TestOptionalUnboundHoldRestartAndFixedMode(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	site, board := domain.NewID(), domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	r := optionalFixture()
	r.Site, r.Board = site, &board
	r.Received = domain.Time(now.Add(-time.Hour).UnixNano())
	r.Finished, r.Until = r.Received+100, r.Received+domain.Time(OptionalRetention)
	if e = s.Write(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	entries, e := s.QueryUnboundSigned(context.Background(), OptionalQueryScope{Board: board, From: r.Received, To: r.Received + 1000}, now)
	if e != nil || len(entries) != 1 {
		t.Fatal(entries, e)
	}
	b := OptionalHoldBinding{Unbound: true, Case: domain.NewID(), Revision: 2, Board: board, From: r.Received, To: r.Received + 1000, Operations: []domain.ID{}, Until: domain.Time(now.Add(30 * 24 * time.Hour).UnixNano())}
	if e = s.ReserveOptionalHold(context.Background(), b, entries, now); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	copy := b
	copy.Unbound = false
	if e = s.ReserveOptionalHold(context.Background(), copy, entries, now); e == nil {
		t.Fatal("hold mode changed")
	}
	cut := now.Add(8 * 24 * time.Hour)
	if n, err := s.Sweep(cut); err != nil || n != 0 {
		t.Fatal("reserved observation reclaimed", n, err)
	}
	held, e := s.QueryOptionalHold(context.Background(), b.Case, cut)
	if e != nil || len(held) != 1 || held[0].Event.EventSHA != entries[0].Event.EventSHA {
		t.Fatal("held observation unavailable after source expiry", held, e)
	}
	if e = s.ReleaseOptionalHold(context.Background(), b.Case, b.Revision, cut); e != nil {
		t.Fatal(e)
	}
	if n, err := s.Sweep(cut); err != nil || n != 1 {
		t.Fatal("released observation retained", n, err)
	}
}

func TestOptionalHoldBindingOldBytesRemainUnchanged(t *testing.T) {
	b := OptionalHoldBinding{Case: domain.NewID(), Revision: 2, Board: domain.NewID(), From: 1, To: 2, Operations: []domain.ID{domain.NewID()}, Until: 3}
	raw, _ := json.Marshal(b)
	var decoded OptionalHoldBinding
	if e := json.Unmarshal(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	after, _ := json.Marshal(decoded)
	if string(raw) != string(after) || decoded.Unbound {
		t.Fatal("old binding bytes changed")
	}
}
