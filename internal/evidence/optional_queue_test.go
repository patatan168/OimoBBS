// 非必須ログの有界受付・二並列保存・欠測集計・停止を通信待ちなしで検査する。
package evidence

import (
	"context"
	"encoding/base64"
	"errors"
	"oimobbs/internal/domain"
	"strings"
	"sync"
	"testing"
	"time"
)

func optionalFixture() OptionalRecord {
	return OptionalRecord{Schema: "optional-http-v1", FinishStage: "handler_return", UAStatus: "captured", ID: domain.NewID(), Site: domain.NewID(), Boot: domain.NewID(), Connection: domain.NewID(), Request: domain.NewID(), Received: 100, Finished: 200, Until: 100 + domain.Time(7*24*time.Hour), Peer: Endpoint{"192.0.2.1", 12345}, Local: Endpoint{"192.0.2.2", 443}, Method: "POST", Route: "legacy_post", Kind: "attempt", Outcome: "rejected", Status: 403, HTTPVersion: "HTTP/1.1"}
}

func TestOptionalQueueBoundedAndDurableAccounting(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	q, e := NewOptionalQueue(func(ctx context.Context, record OptionalRecord) error {
		started <- struct{}{}
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if e != nil {
		t.Fatal(e)
	}
	// 保存中も受付上限へ含め、workerが取り出すだけで予約を返却しない。
	for i := 0; i < MaxOptionalRecords; i++ {
		if !q.Enqueue(optionalFixture()) {
			t.Fatal("early drop", i)
		}
	}
	<-started
	<-started
	if q.Enqueue(optionalFixture()) {
		t.Fatal("inflight capacity was freed")
	}
	status := q.Status()
	if status.Pending != MaxOptionalRecords || status.DroppedCapacity != 1 || status.Saved != 0 || status.PendingBytes > MaxOptionalBytes {
		t.Fatal(status)
	}
	// 後続callbackの通知で保存workerを止めない。
	go func() {
		for range started {
		}
	}()
	close(release)
	if e = q.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	close(started)
	status = q.Status()
	if status.Saved != MaxOptionalRecords || status.Pending != 0 || status.PendingBytes != 0 || !status.Closed {
		t.Fatal(status)
	}
	if q.Enqueue(optionalFixture()) || q.Status().DroppedClosed != 1 {
		t.Fatal("closed queue admitted record")
	}
}

func TestOptionalQueueFailureInvalidAndShutdown(t *testing.T) {
	q, e := NewOptionalQueue(func(context.Context, OptionalRecord) error { return errors.New("private failure text") })
	if e != nil {
		t.Fatal(e)
	}
	bad := optionalFixture()
	bad.Route = "/test/bbs.cgi?password=secret"
	if q.Enqueue(bad) {
		t.Fatal("raw route admitted")
	}
	if !q.Enqueue(optionalFixture()) {
		t.Fatal("enqueue")
	}
	if e = q.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	status := q.Status()
	if status.Failed != 1 || status.DroppedInvalid != 1 || status.LossStarted == 0 || status.LossFinished < status.LossStarted {
		t.Fatal(status)
	}

	started := make(chan struct{}, 2)
	q, e = NewOptionalQueue(func(ctx context.Context, _ OptionalRecord) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if !q.Enqueue(optionalFixture()) {
			t.Fatal("enqueue")
		}
	}
	<-started
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = q.Close(ctx); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	<-q.Done()
	status = q.Status()
	if status.Pending != 0 || status.PendingBytes != 0 || status.Failed+status.DroppedShutdown != 3 {
		t.Fatal(status)
	}
}

func TestOptionalQueueConcurrentRecordOwnership(t *testing.T) {
	var mu sync.Mutex
	values := []string{}
	release := make(chan struct{})
	board, operation := domain.NewID(), domain.NewID()
	wantBoard, wantOperation := board, operation
	version, cipher := uint16(0x304), uint16(0x1301)
	q, e := NewOptionalQueue(func(_ context.Context, record OptionalRecord) error {
		<-release
		mu.Lock()
		defer mu.Unlock()
		if *record.Board != wantBoard || *record.Operation != wantOperation || *record.TLSVersion != 0x304 || *record.TLSCipher != 0x1301 {
			return errors.New("caller changed queued fields")
		}
		values = append(values, record.UserAgent.Display)
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	r := optionalFixture()
	r.UserAgent = &HeaderValue{Base64: "dWE=", Display: "ua"}
	r.Board, r.Operation = &board, &operation
	r.TLSVersion, r.TLSCipher = &version, &cipher
	r.Outcome = "accepted"
	if !q.Enqueue(r) {
		t.Fatal("enqueue")
	}
	r.UserAgent.Display = "changed"
	board, operation = domain.ID{}, domain.ID{}
	version, cipher = 0, 0
	close(release)
	if e = q.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(values) != 1 || values[0] != "ua" {
		t.Fatal(values)
	}
}

func TestOptionalQueueByteCapacity(t *testing.T) {
	q, e := NewOptionalQueue(func(ctx context.Context, _ OptionalRecord) error { <-ctx.Done(); return ctx.Err() })
	if e != nil {
		t.Fatal(e)
	}
	r := optionalFixture()
	value := strings.Repeat("u", MaxObservedHeaderBytes)
	r.UserAgent = &HeaderValue{Base64: base64.StdEncoding.EncodeToString([]byte(value)), Display: value}
	n := 0
	for q.Enqueue(r) {
		n++
	}
	status := q.Status()
	if n == 0 || n >= MaxOptionalRecords || status.PendingBytes > MaxOptionalBytes || status.PendingBytes < MaxOptionalBytes-MaxOptionalRecordBytes || status.DroppedCapacity != 1 {
		t.Fatal(n, status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = q.Close(ctx)
	<-q.Done()
	if q.Status().PendingBytes != 0 {
		t.Fatal("byte reservation remained")
	}
}
