// 回収量に応じた予約、予約拒否時の原本保持、先に始まった要求の保存を検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestOptionalSweepReservationsAndPendingRequestClock(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	site := domain.NewID()
	root := t.TempDir()
	os.Chmod(root, 0700)
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	// 原本は過去の耐久保存を模したもの。cutoffは実時計より前に固定する。
	cutoff := time.Now().UTC().Truncate(24 * time.Hour).Add(-12 * time.Hour)
	at := domain.Time(cutoff.UnixNano())
	received := cutoff.Add(-OptionalRetention - time.Hour)
	text := received.UTC().Format("20060102")
	day, _ := strconv.ParseUint(text, 10, 64)
	path := filepath.Join(root, text)
	j, e := OpenJournal(path, s.owner, day, 10, key, s.validate)
	if e != nil {
		t.Fatal(e)
	}
	s.journals[day] = j
	appendRecord := func(received time.Time) Event {
		t.Helper()
		r := optionalFixture()
		r.Site = site
		r.Received = domain.Time(received.UnixNano())
		r.Finished = r.Received + 100
		r.Until = r.Received + domain.Time(OptionalRetention)
		event, result := j.Append(r.ID, "attempt", r.Finished, func(src Source) ([]byte, error) {
			return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), r})
		})
		if result.Status != store.Durable {
			t.Fatal(result)
		}
		return event
	}
	for i := 0; i < 300; i++ {
		appendRecord(received)
	}
	live := appendRecord(cutoff.Add(-OptionalRetention + time.Hour))
	wal := filepath.Join(path, "control-000001.wal")
	before, _ := os.ReadFile(wal)
	refusal := errors.New("reserved elsewhere")
	if n, e := s.SweepReserved(cutoff, func(int64) (func(), error) { return nil, refusal }); n != 0 || !errors.Is(e, refusal) {
		t.Fatal(n, e)
	}
	after, _ := os.ReadFile(wal)
	if string(before) != string(after) {
		t.Fatal("reservation refusal changed original")
	}
	allocations, releases := 0, 0
	n, e := s.SweepReserved(cutoff, func(bytes int64) (func(), error) {
		allocations++
		if bytes != MaxOptionalDayBytes+(256<<10) {
			t.Fatal("partial snapshot reservation", bytes)
		}
		return func() { releases++ }, nil
	})
	if e != nil || n != 300 || allocations != 1 || releases != 1 || s.CleanupFailed() {
		t.Fatal(n, e, allocations, releases)
	}
	if s.floor != at {
		t.Fatal("cleanup boundary missing")
	}
	found := false
	for _, row := range j.entries {
		if row.Event.RecordID == live.RecordID {
			found = true
			if row.Event != live {
				t.Fatal("retained signature changed")
			}
		}
	}
	if !found {
		t.Fatal("retained source missing")
	}
	if _, e = os.Stat(wal); !os.IsNotExist(e) {
		t.Fatal("old WAL remained", e)
	}
	// 受付が回収開始前でも、実時計は巻き戻っていない。未満了の待機要求は保存できる。
	queued := optionalFixture()
	queued.Site = site
	queued.Received = at - 100
	queued.Finished = at + 100
	queued.Until = queued.Received + domain.Time(OptionalRetention)
	if e = s.Write(context.Background(), queued); e != nil {
		t.Fatal("valid pending request mistaken for clock regression", e)
	}
}

func TestOptionalSweepFullDaySmallReservationAndNoSourceReuse(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	site := domain.NewID()
	root := t.TempDir()
	os.Chmod(root, 0700)
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	cutoff := time.Now()
	received := cutoff.UTC().Truncate(24 * time.Hour).Add(-OptionalRetention)
	text := received.UTC().Format("20060102")
	day, _ := strconv.ParseUint(text, 10, 64)
	j, e := OpenJournal(filepath.Join(root, text), s.owner, day, 10, key, s.validate)
	if e != nil {
		t.Fatal(e)
	}
	s.journals[day] = j
	r := optionalFixture()
	r.Site = site
	r.Received = domain.Time(received.UnixNano())
	r.Finished = r.Received + 100
	r.Until = r.Received + domain.Time(OptionalRetention)
	_, result := j.Append(r.ID, "attempt", r.Finished, func(src Source) ([]byte, error) {
		return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), r})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	released := false
	n, e := s.SweepReserved(cutoff, func(bytes int64) (func(), error) {
		if bytes != 128<<10 {
			t.Fatal("full day required snapshot capacity", bytes)
		}
		return func() { released = true }, nil
	})
	if n != 1 || e != nil || !released {
		t.Fatal(n, e, released)
	}
	if _, e = os.Stat(filepath.Join(root, text)); !os.IsNotExist(e) {
		t.Fatal("expired original remained", e)
	}
	// 同じUTC日の生存期限を持つ遅延記録でも、終端sourceをseq=1へ戻して再作成しない。
	candidate := r
	candidate.ID = domain.NewID()
	candidate.Received = domain.Time(received.Add(24*time.Hour - time.Millisecond).UnixNano())
	candidate.Finished = candidate.Received + 100
	candidate.Until = candidate.Received + domain.Time(OptionalRetention)
	if time.Unix(0, int64(candidate.Received)).UTC().Format("20060102") != text || candidate.Until <= domain.Time(time.Now().UnixNano()) {
		t.Fatal("source reuse fixture does not remain alive on the same day")
	}
	if e = s.Write(context.Background(), candidate); e == nil {
		t.Fatal("terminal source reused")
	}
}

func TestStoppedReclaimDoesNotResumeUnderWriterReservation(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	site := domain.NewID()
	root := t.TempDir()
	os.Chmod(root, 0700)
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	received := now.UTC().Truncate(24 * time.Hour).Add(-OptionalRetention)
	text := received.UTC().Format("20060102")
	day, _ := strconv.ParseUint(text, 10, 64)
	path := filepath.Join(root, text)
	j, e := OpenJournal(path, s.owner, day, 10, key, s.validate)
	if e != nil {
		t.Fatal(e)
	}
	s.journals[day] = j
	makeRecord := func(received time.Time) OptionalRecord {
		r := optionalFixture()
		r.Site = site
		r.Received = domain.Time(received.UnixNano())
		r.Finished = r.Received + 100
		r.Until = r.Received + domain.Time(OptionalRetention)
		return r
	}
	appendRecord := func(r OptionalRecord) {
		t.Helper()
		_, result := j.Append(r.ID, "attempt", r.Finished, func(src Source) ([]byte, error) {
			return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), r})
		})
		if result.Status != store.Durable {
			t.Fatal(result)
		}
	}
	for i := 0; i < 129; i++ {
		appendRecord(makeRecord(received))
	}
	live := makeRecord(received.Add(24*time.Hour - time.Millisecond))
	appendRecord(live)
	n, e := j.PruneOptionalAll(domain.Time(now.UnixNano()), func(stage string) error {
		if stage == "optional:removed" {
			return store.ErrIncomplete
		}
		return nil
	})
	if n != 128 || e == nil || !j.optionalReclaimPending {
		t.Fatal("reclaim did not stop", n, e)
	}
	wal := filepath.Join(path, "control-000001.wal")
	before, _ := os.ReadFile(wal)
	live.ID = domain.NewID()
	if e = s.Write(context.Background(), live); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("writer attempted unreserved snapshot recovery", e)
	}
	after, _ := os.ReadFile(wal)
	if string(before) != string(after) {
		t.Fatal("writer changed stopped reclamation")
	}
	n, e = s.SweepReserved(now, func(bytes int64) (func(), error) {
		if bytes != MaxOptionalDayBytes+(256<<10) {
			t.Fatal("recovery reservation", bytes)
		}
		return func() {}, nil
	})
	if n != 1 || e != nil {
		t.Fatal(n, e)
	}
	if e = s.Write(context.Background(), live); e != nil {
		t.Fatal("writer did not resume after reserved recovery", e)
	}
}
