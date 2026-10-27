// 非必須照会の板/操作/期間/期限境界、所有権、上限と回収競合を実署名fileで検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestOptionalQueryScopeExpiryAndOwnership(t *testing.T) {
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer clear(key)
	site, board, operation := domain.NewID(), domain.NewID(), domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	base := optionalFixture()
	base.Site = site
	base.Board = &board
	base.Operation = &operation
	base.Outcome = "accepted"
	base.Received = domain.Time(now.Add(-time.Hour).UnixNano())
	base.Finished = base.Received + 100
	base.Until = base.Received + domain.Time(OptionalRetention)
	scope := OptionalQueryScope{Board: board, From: base.Received, To: base.Received + 1000, Operations: []domain.ID{operation}}
	if e = s.Write(context.Background(), base); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"board", "operation", "unresolved", "period"} {
		r := base
		r.ID = domain.NewID()
		switch kind {
		case "board":
			other := domain.NewID()
			r.Board = &other
		case "operation":
			other := domain.NewID()
			r.Operation = &other
		case "unresolved":
			r.Board = nil
		case "period":
			r.Received = scope.To
			r.Finished = r.Received + 100
			r.Until = r.Received + domain.Time(OptionalRetention)
		}
		if e = s.Write(context.Background(), r); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := optionalRecordsForTest(s, false, context.Background(), scope, now)
	if e != nil || len(rows) != 1 || rows[0].Record.ID != base.ID {
		t.Fatal(rows, e)
	}
	*rows[0].Record.Board = domain.NewID()
	*rows[0].Record.Operation = domain.NewID()
	again, e := optionalRecordsForTest(s, false, context.Background(), scope, now)
	if e != nil || len(again) != 1 || *again[0].Record.Board != board {
		t.Fatal("query alias modified source", again, e)
	}
	s.Close()
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	restored, e := optionalRecordsForTest(s, false, context.Background(), scope, now)
	if e != nil || len(restored) != 1 || restored[0].SourceSHA != again[0].SourceSHA {
		t.Fatal(restored, e)
	}
	expired, e := optionalRecordsForTest(s, false, context.Background(), scope, time.Unix(0, int64(base.Until)))
	if e != nil || len(expired) != 0 {
		t.Fatal("expired unswept row disclosed", expired, e)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, e := optionalRecordsForTest(s, false, cancelled, scope, now); !errors.Is(e, context.Canceled) || rows != nil {
		t.Fatal(rows, e)
	}
	duplicate := scope
	duplicate.Operations = append(duplicate.Operations, operation)
	if _, e := optionalRecordsForTest(s, false, context.Background(), duplicate, now); !errors.Is(e, ErrOptionalQueryScope) {
		t.Fatal(e)
	}
	// 列の保存不明を照会の小さな枠で復旧しない。
	for _, j := range s.journals {
		j.stopped = true
	}
	if rows, e := optionalRecordsForTest(s, false, context.Background(), scope, now); !errors.Is(e, store.ErrIncomplete) || rows != nil {
		t.Fatal(rows, e)
	}
}

func TestOptionalQueryLimitAndSweepConcurrency(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	defer clear(key)
	site, board, operation := domain.NewID(), domain.NewID(), domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now()
	r := optionalFixture()
	r.Site = site
	r.Board = &board
	r.Operation = &operation
	r.Outcome = "accepted"
	r.Received = domain.Time(now.Add(-OptionalRetention + time.Minute).UnixNano())
	r.Finished = r.Received + 100
	r.Until = r.Received + domain.Time(OptionalRetention)
	scope := OptionalQueryScope{Board: board, From: r.Received, To: r.Received + 1000, Operations: []domain.ID{operation}}
	for i := 0; i <= MaxOptionalQueryRecords; i++ {
		r.ID = domain.NewID()
		if e = s.Write(context.Background(), r); e != nil {
			t.Fatal(e)
		}
	}
	if rows, e := optionalRecordsForTest(s, false, context.Background(), scope, now); !errors.Is(e, ErrOptionalQueryLimit) || rows != nil {
		t.Fatal("partial overflow returned", len(rows), e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rows, e := optionalRecordsForTest(s, false, context.Background(), scope, now.Add(2*time.Minute))
			if e != nil || len(rows) != 0 {
				t.Errorf("expired row in concurrent query: %d %v", len(rows), e)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, e := s.Sweep(now.Add(2 * time.Minute)); e != nil {
			t.Error(e)
		}
	}()
	wg.Wait()
}

// optionalRecordsForTest は保全で使用する署名付き取得経路を検査用の値へ復号する。
func optionalRecordsForTest(s *OptionalStore, unbound bool, ctx context.Context, scope OptionalQueryScope, now time.Time) ([]OptionalEvidence, error) {
	var entries []Entry
	var err error
	if unbound {
		entries, err = s.QueryUnboundSigned(ctx, scope, now)
	} else {
		entries, err = s.QuerySigned(ctx, scope, now)
	}
	if err != nil {
		return nil, err
	}
	rows := make([]OptionalEvidence, 0, len(entries))
	for _, entry := range entries {
		var p OptionalPayload
		if err := strictjson.Decode(entry.Payload, &p); err != nil {
			return nil, err
		}
		rows = append(rows, OptionalEvidence{p.Owner, p.Day, p.Seq, entry.Event.EventSHA, p.Record})
	}
	return rows, nil
}
