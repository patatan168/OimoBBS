// 有界キュー満杯の二workerと部分満了回収を同時実行し、既受付記録の欠測を検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOptionalReclaimWhileQueueBusy(t *testing.T) {
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
	expiredReceived := now.UTC().Truncate(24 * time.Hour).Add(-OptionalRetention)
	dayText := expiredReceived.UTC().Format("20060102")
	day, _ := strconv.ParseUint(dayText, 10, 64)
	path := filepath.Join(root, dayText)
	j, e := OpenJournal(path, s.owner, day, 10, key, s.validate)
	if e != nil {
		t.Fatal(e)
	}
	s.journals[day] = j
	appendOld := func(received time.Time) {
		t.Helper()
		r := optionalFixture()
		r.Site = site
		r.Received = domain.Time(received.UnixNano())
		r.Finished = r.Received + 100
		r.Until = r.Received + domain.Time(OptionalRetention)
		ua := encodeHeaderValue(strings.Repeat("x", 6000))
		r.UserAgent = &ua
		_, result := j.Append(r.ID, "attempt", r.Finished, func(src Source) ([]byte, error) {
			return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), r})
		})
		if result.Status != store.Durable {
			t.Fatal(result)
		}
	}
	for i := 0; i < 1025; i++ {
		appendOld(expiredReceived)
	}
	appendOld(expiredReceived.Add(24*time.Hour - time.Millisecond))
	received := domain.Time(time.Now().Add(-2 * time.Second).UnixNano())
	release := make(chan struct{})
	q, e := NewOptionalQueue(func(ctx context.Context, r OptionalRecord) error {
		select {
		case <-release:
			return s.Write(ctx, r)
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
		q.Close(context.Background())
	}()
	for i := 0; i < MaxOptionalRecords; i++ {
		r := optionalFixture()
		r.Site = site
		r.Received = received
		r.Finished = received + 100
		r.Until = received + domain.Time(OptionalRetention)
		if !q.Enqueue(r) {
			t.Fatal("queue rejected bounded load", i)
		}
	}
	entered := make(chan struct{})
	done := make(chan error, 1)
	started := time.Now()
	go func() {
		n, e := s.SweepReserved(started, func(int64) (func(), error) { close(entered); return func() {}, nil })
		if e == nil && n != 1025 {
			e = store.ErrCorrupt
		}
		done <- e
	}()
	<-entered // Store所有mutexの内側で回収予約が成立した境界。
	close(release)
	if e = <-done; e != nil {
		t.Fatal(e)
	}
	reclaimed := time.Since(started)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e = q.Close(ctx); e != nil {
		t.Fatal(e)
	}
	status := q.Status()
	if status.Saved != MaxOptionalRecords || status.Failed != 0 || status.Pending != 0 {
		t.Fatal("pending request lost during GC", status)
	}
	if reclaimed >= 5*time.Minute {
		t.Fatal("loaded reclaim missed five-minute bound", reclaimed)
	}
	t.Logf("expired=1025 retained=1 queued=%d workers=2 reclaim=%s queue_drain=%s", MaxOptionalRecords, reclaimed, time.Since(started))
	if _, e = os.Stat(filepath.Join(path, "control-000001.wal")); !os.IsNotExist(e) {
		t.Fatal("old private bytes remained", e)
	}
	if j.seq != 1035 || len(j.entries) != 10 {
		t.Fatal("loaded recovery chain", j.seq, len(j.entries))
	}
}
