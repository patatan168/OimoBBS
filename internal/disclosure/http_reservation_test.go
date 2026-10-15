// 案件intentと実元所有列予約をつなぎ、コピー停止中の満了・再起動・参照不一致を検査する。
package disclosure

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func reservedHTTPFixture(t *testing.T) (*Store, *evidence.OptionalStore, Case, domain.ID, evidence.OptionalHoldReceipt, []evidence.Entry, time.Time, ed25519.PrivateKey) {
	return reservedHTTPFixtureWithReference(t, true)
}

// reservedHTTPFixtureWithReference は参照Sync前の停止点も同じ実元予約から作る。
func reservedHTTPFixtureWithReference(t *testing.T, bind bool) (*Store, *evidence.OptionalStore, Case, domain.ID, evidence.OptionalHoldReceipt, []evidence.Entry, time.Time, ed25519.PrivateKey) {
	t.Helper()
	s, key, c, actor, now, site, entry := httpHoldFixture(t)
	c, e := s.PrepareHTTPHold(c.ID, actor, c.ETag(), "prepare-http", "hold", site, []evidence.Entry{entry}, now)
	if e != nil || c.HTTP.State != "preparing" {
		t.Fatal(c, e)
	}
	if _, e := os.Stat(s.httpPath(c.ID, entry.Event.RecordID)); !os.IsNotExist(e) {
		t.Fatal("prepare copied before reservation", e)
	}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	owner, e := evidence.OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { owner.Close() })
	var p evidence.OptionalPayload
	if e := json.Unmarshal(entry.Payload, &p); e != nil {
		t.Fatal(e)
	}
	if e := owner.Write(context.Background(), p.Record); e != nil {
		t.Fatal(e)
	}
	binding, e := s.HTTPReservationBinding(c, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e := owner.ReserveOptionalHold(context.Background(), binding, []evidence.Entry{entry}, time.Now()); e != nil {
		t.Fatal(e)
	}
	receipt, found, e := owner.OptionalHoldReceipt(c.ID)
	if e != nil || !found {
		t.Fatal(e)
	}
	if bind {
		c, e = s.BindHTTPReservation(c.ID, actor, c.ETag(), receipt, time.Now())
		if e != nil {
			t.Fatal(e)
		}
	}
	return s, owner, c, actor, receipt, []evidence.Entry{entry}, now, key
}

// reservationCheck は所有列の最新耐久参照を照合し、解放済み参照の使い回しを拒否する。
func reservationCheck(owner *evidence.OptionalStore, receipt evidence.OptionalHoldReceipt) func() error {
	return func() error {
		current, found, e := owner.OptionalHoldReceipt(receipt.Binding.Case)
		if e != nil {
			return e
		}
		if !found || current.State != "active" || current.SHA != receipt.SHA || current.Sequence != receipt.Sequence {
			return store.ErrIncomplete
		}
		return nil
	}
}

func TestHTTPReservationCopyStopExpiryAndRestart(t *testing.T) {
	s, owner, c, actor, receipt, entries, now, key := reservedHTTPFixture(t)
	injected := errors.New("copy stopped")
	s.checkpoint = func(at string) error {
		if at == "http_hold:file" {
			return injected
		}
		return nil
	}
	_, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, receipt, time.Now(), reservationCheck(owner, receipt))
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	cut := now.Add(8 * 24 * time.Hour)
	if n, e := owner.Sweep(cut); e != nil || n != 0 {
		t.Fatal("copy failure lost original", n, e)
	}
	reserved, e := owner.QueryOptionalHold(context.Background(), c.ID, cut)
	if e != nil || len(reserved) != 1 {
		t.Fatal(reserved, e)
	}
	root := s.root
	s.Close()
	s, e = Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ResumeHTTPReserved(c.ID, actor, c.ETag(), reserved, receipt, cut, reservationCheck(owner, receipt))
	if e != nil || c.HTTP.State != "active" {
		t.Fatal(c, e)
	}
	if e := owner.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, cut); e != nil {
		t.Fatal(e)
	}
	if n, e := owner.Sweep(cut); e != nil || n != 1 {
		t.Fatal("copy complete did not permit GC", n, e)
	}
	if rows, e := s.HTTPRecords(c, cut); e != nil || len(rows) != 1 {
		t.Fatal("independent case copy lost", rows, e)
	}
	if e := InspectVersion(root, key, 41); e == nil {
		t.Fatal("old reader accepted reservation reference")
	}
	if e := InspectVersion(root, key, 42); e != nil {
		t.Fatal(e)
	}
}

func TestHTTPReservationMissingCopyAfterOriginalExpiry(t *testing.T) {
	s, owner, c, actor, receipt, _, now, _ := reservedHTTPFixture(t)
	cut := now.Add(8 * 24 * time.Hour)
	if n, e := owner.Sweep(cut); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	reserved, e := owner.QueryOptionalHold(context.Background(), c.ID, cut)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ResumeHTTPReserved(c.ID, actor, c.ETag(), reserved, receipt, cut, reservationCheck(owner, receipt))
	if e != nil || c.HTTP.State != "active" {
		t.Fatal("expired original not copied under reservation", c, e)
	}
}

func TestHTTPReservationRejectsStaleChangedOrAbsentProof(t *testing.T) {
	s, owner, c, actor, receipt, entries, _, _ := reservedHTTPFixture(t)
	if _, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, receipt, time.Now(), nil); e == nil {
		t.Fatal("missing live check accepted")
	}
	changed := receipt
	changed.Site = domain.NewID()
	if _, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, changed, time.Now(), reservationCheck(owner, receipt)); e == nil {
		t.Fatal("cross-site reference accepted")
	}
	changed = receipt
	changed.SHA[0] ^= 1
	if _, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, changed, time.Now(), reservationCheck(owner, receipt)); e == nil {
		t.Fatal("changed reference accepted")
	}
	if e := owner.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, receipt, time.Now(), reservationCheck(owner, receipt)); e == nil {
		t.Fatal("released reference reused")
	}
	current, e := s.Get(c.ID)
	if e != nil || current.HTTP.State != "preparing" {
		t.Fatal("failed proof changed completion", current, e)
	}
}

// ファイルSync後に元予約が失効した場合も、古い参照でcompleteへ進めない。
func TestHTTPReservationStopsCompletionWhenOwnerChanges(t *testing.T) {
	s, owner, c, actor, receipt, entries, _, _ := reservedHTTPFixture(t)
	checks := 0
	check := func() error {
		checks++
		if checks == 3 {
			if e := owner.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
				return e
			}
		}
		return reservationCheck(owner, receipt)()
	}
	returned, resumeErr := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, receipt, time.Now(), check)
	if resumeErr == nil {
		t.Fatal("released owner completed copy")
	}
	if returned.HTTP.State != "preparing" {
		t.Fatal("failed copy returned uncommitted active state", returned.HTTP.State)
	}
	current, e := s.Get(c.ID)
	if e != nil || current.HTTP.State != "preparing" {
		t.Fatal(current, e)
	}
	if _, e := os.Stat(s.httpPath(c.ID, entries[0].Event.RecordID)); e != nil {
		t.Fatal("durable copy lost on failed complete", e)
	}
}

// 元参照更新は固定対象を変更せず、古い版/seqの参照に戻さない。
func TestHTTPReservationBindingRejectsChangedTarget(t *testing.T) {
	s, owner, c, actor, receipt, entries, _, _ := reservedHTTPFixture(t)
	changed := receipt
	changed.Items = append([]evidence.OptionalHoldSource{}, receipt.Items...)
	changed.Items[0].Record = domain.NewID()
	if _, e := s.BindHTTPReservation(c.ID, actor, c.ETag(), changed, time.Now()); e == nil {
		t.Fatal("target changed in reservation bind")
	}
	changed = receipt
	changed.Binding.Revision = c.Revision + 1
	if _, e := s.BindHTTPReservation(c.ID, actor, c.ETag(), changed, time.Now()); e == nil {
		t.Fatal("uncommitted case revision bound")
	}
	if _, e := s.BindHTTPReservation(c.ID, actor, c.ETag(), receipt, time.Now()); e != nil {
		t.Fatal("same reference replay", e)
	}
	current, e := s.Get(c.ID)
	if e != nil || current.Revision != c.Revision {
		t.Fatal("same reference duplicated case row", current, e)
	}
	if _, e := s.ResumeHTTPReserved(c.ID, actor, c.ETag(), nil, receipt, time.Now(), reservationCheck(owner, receipt)); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("missing reserved source marked successful", e)
	}
	if _, e := os.Stat(s.httpPath(c.ID, entries[0].Event.RecordID)); !os.IsNotExist(e) {
		t.Fatal("failed reserved copy created target", e)
	}
}

// 元更新Sync後・案件参照未保存からの再開は、直後参照を保存してから次の更新へ進む。
func TestHTTPReservationAdoptUnreflectedNextBeforeRenew(t *testing.T) {
	s, owner, c, actor, first, entries, _, _ := reservedHTTPFixture(t)
	binding, e := s.HTTPReservationBinding(c, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e := owner.ReserveOptionalHold(context.Background(), binding, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	next, e := owner.CheckOptionalHoldReceipt(first)
	if e != nil || next.Sequence != first.Sequence+1 {
		t.Fatal(next, e)
	}
	c, e = s.PrepareHTTPHold(c.ID, actor, c.ETag(), "retry-with-unreflected-source", "hold", first.Site, entries, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.BindHTTPReservation(c.ID, actor, c.ETag(), next, time.Now())
	if e != nil {
		t.Fatal("adopt source before renewal", e)
	}
	binding, e = s.HTTPReservationBinding(c, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if e := owner.ReserveOptionalHold(context.Background(), binding, entries, time.Now()); e != nil {
		t.Fatal(e)
	}
	renewed, e := owner.CheckOptionalHoldReceipt(*c.HTTP.Reservation)
	if e != nil || renewed.Sequence != next.Sequence+1 {
		t.Fatal("renewal skipped reference link", renewed, e)
	}
	c, e = s.BindHTTPReservation(c.ID, actor, c.ETag(), renewed, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ResumeHTTPReserved(c.ID, actor, c.ETag(), entries, renewed, time.Now(), reservationCheck(owner, renewed))
	if e != nil || c.HTTP.State != "active" {
		t.Fatal(c, e)
	}
	if e := owner.ReleaseOptionalHold(context.Background(), c.ID, c.Revision, time.Now()); e != nil {
		t.Fatal(e)
	}
	released, e := owner.CheckOptionalHoldReceipt(*c.HTTP.Reservation)
	if e != nil || released.State != "released" {
		t.Fatal("completion release link lost", released, e)
	}
}
