// 一括保存の耐久境界・不変状態・再起動時の整合性を検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOptionalBatchQueueDrainAndAccounting(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var sizes []int
	var mu sync.Mutex
	q, e := NewOptionalBatchQueue(func(_ context.Context, records []OptionalRecord) []error {
		mu.Lock()
		sizes = append(sizes, len(records))
		first := len(sizes) == 1
		mu.Unlock()
		if first {
			close(started)
			<-release
		}
		result := make([]error, len(records))
		for i, r := range records {
			if r.Status == 500 {
				result[i] = errors.New("injected")
			}
		}
		return result
	})
	if e != nil {
		t.Fatal(e)
	}
	if !q.Enqueue(optionalFixture()) {
		t.Fatal("first")
	}
	<-started
	for i := 0; i < 66; i++ {
		r := optionalFixture()
		if i == 65 {
			r.Status = 500
		}
		if !q.Enqueue(r) {
			t.Fatal("enqueue")
		}
	}
	if status := q.Status(); status.Saved != 0 || status.Pending != 67 {
		t.Fatal("early saved", status)
	}
	close(release)
	if e = q.Close(context.Background()); e != nil {
		t.Fatal(e)
	}
	if status := q.Status(); status.Saved != 66 || status.Failed != 1 || status.Pending != 0 || status.PendingBytes != 0 {
		t.Fatal(status)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sizes) != 3 || sizes[0] != 1 || sizes[1] != 64 || sizes[2] != 2 {
		t.Fatal("drain", sizes)
	}
}

// 長い試験用窓でも、64件到達・Close・取消が窓を待たず予約を解放する。
func TestOptionalBatchWindowBoundaries(t *testing.T) {
	for _, mode := range []string{"full", "close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			written := make(chan int, 1)
			q := &OptionalQueue{queue: make(chan *optionalQueuedRecord, MaxOptionalRecords), done: make(chan struct{}), cancel: cancel, batchWait: time.Hour,
				batchWrite: func(_ context.Context, records []OptionalRecord) []error {
					written <- len(records)
					return make([]error, len(records))
				}}
			go func() { defer close(q.done); q.run(ctx) }()
			defer func() { cancel(); _ = q.Close(context.Background()) }()
			count := 7
			if mode == "full" {
				count = MaxOptionalBatch
			}
			for i := 0; i < count; i++ {
				if !q.Enqueue(optionalFixture()) {
					t.Fatal("enqueue")
				}
			}
			if mode == "cancel" {
				cancel()
			} else if mode == "full" {
				select {
				case size := <-written:
					if size != count {
						t.Fatal("split full batch", size)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("full batch waited for window")
				}
			}
			deadline, finish := context.WithTimeout(context.Background(), 5*time.Second)
			defer finish()
			if e := q.Close(deadline); e != nil {
				t.Fatal("close waited for window", e)
			}
			status := q.Status()
			if status.Pending != 0 || status.PendingBytes != 0 || mode == "cancel" && (status.Saved != 0 || status.DroppedShutdown != uint64(count)) || mode != "cancel" && status.Saved != uint64(count) {
				t.Fatal("reservation accounting", status)
			}
			if mode == "close" {
				if size := <-written; size != count {
					t.Fatal("close split batch", size)
				}
			}
		})
	}
}

func TestOptionalStoreBatchChainAcrossDaysAndRestart(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	os.Chmod(root, 0700)
	site := domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	makeRecord := func(at time.Time) OptionalRecord {
		r := optionalFixture()
		r.Site = site
		r.Received = domain.Time(at.UnixNano())
		r.Finished = r.Received + 100
		r.Until = r.Received + domain.Time(OptionalRetention)
		return r
	}
	now := time.Now().UTC()
	var records []OptionalRecord
	for i := 0; i < 70; i++ {
		at := now
		if i >= 35 {
			at = now.Add(-24 * time.Hour)
		}
		records = append(records, makeRecord(at))
	}
	for i, e := range s.WriteBatch(context.Background(), records) {
		if e != nil {
			t.Fatal(i, e)
		}
	}
	if len(s.journals) != 2 {
		t.Fatal("days")
	}
	// 全件に対して単独時と同じ予約上限を保ち、実frameのbytes以上を確保する。
	for _, j := range s.journals {
		if len(j.entries) != 35 || j.seq != 35 {
			t.Fatal("entries")
		}
	}
	s.Close()
	s, e = OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal("signed replay", e)
	}
	defer s.Close()
	for _, j := range s.journals {
		if len(j.entries) != 35 || j.seq != 35 {
			t.Fatal("recovered")
		}
	}
	r := makeRecord(now)
	invalid := r
	invalid.ID = domain.NewID()
	invalid.Site = domain.NewID()
	results := s.WriteBatch(context.Background(), []OptionalRecord{r, invalid})
	if results[0] == nil || results[1] == nil {
		t.Fatal("partial validation accepted")
	}
	for _, j := range s.journals {
		if j.seq != 35 {
			t.Fatal("invalid batch changed journal")
		}
	}
	// 同じbatchでIDを再利用した場合も、追加前に全体を拒否する。
	results = s.WriteBatch(context.Background(), []OptionalRecord{r, r})
	if results[0] == nil || results[1] == nil {
		t.Fatal("duplicate batch")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s.WriteBatch(ctx, []OptionalRecord{r})[0] == nil {
		t.Fatal("cancelled write")
	}
}

// 一括保存中も1024件の予約を保持し、停止取消を保存済みへ数えない。
func TestOptionalBatchQueueCapacityAndShutdown(t *testing.T) {
	started := make(chan struct{})
	q, e := NewOptionalBatchQueue(func(ctx context.Context, records []OptionalRecord) []error {
		close(started)
		<-ctx.Done()
		result := make([]error, len(records))
		for i := range result {
			result[i] = ctx.Err()
		}
		return result
	})
	if e != nil {
		t.Fatal(e)
	}
	if !q.Enqueue(optionalFixture()) {
		t.Fatal("first")
	}
	<-started
	for i := 1; i < MaxOptionalRecords; i++ {
		if !q.Enqueue(optionalFixture()) {
			t.Fatal("early capacity", i)
		}
	}
	if q.Enqueue(optionalFixture()) {
		t.Fatal("inflight not reserved")
	}
	if status := q.Status(); status.Pending != MaxOptionalRecords || status.Saved != 0 || status.DroppedCapacity != 1 {
		t.Fatal(status)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if q.Close(ctx) == nil {
		t.Fatal("shutdown not cancelled")
	}
	<-q.Done()
	if status := q.Status(); status.Saved != 0 || status.Failed != 1 || status.DroppedShutdown != MaxOptionalRecords-1 || status.Pending != 0 || status.PendingBytes != 0 {
		t.Fatal(status)
	}
}

// 最大ヘッダを含む64件でも、共通予約が実WAL増分を下回らない。
func TestOptionalBatchReservationCoversWAL(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	os.Chmod(root, 0700)
	site := domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now().UTC()
	at := domain.Time(now.UnixNano())
	records := make([]OptionalRecord, MaxOptionalBatch)
	for i := range records {
		r := optionalFixture()
		r.Site = site
		r.Received = at
		r.Finished = at + 100
		r.Until = at + domain.Time(OptionalRetention)
		ua := strings.Repeat("u", MaxObservedHeaderBytes)
		r.UserAgent = &HeaderValue{Base64: base64.StdEncoding.EncodeToString([]byte(ua)), Display: ua}
		records[i] = r
	}
	reservation, e := OptionalBatchReservation(records)
	if e != nil {
		t.Fatal(e)
	}
	for _, e := range s.WriteBatch(context.Background(), records) {
		if e != nil {
			t.Fatal(e)
		}
	}
	day, _ := strconv.ParseUint(now.Format("20060102"), 10, 64)
	info, e := os.Stat(filepath.Join(root, strconv.FormatUint(day, 10), "control-000001.wal"))
	if e != nil {
		t.Fatal(e)
	}
	if info.Size() > reservation {
		t.Fatal("under-reserved WAL", info.Size(), reservation)
	}
}

// 日別残量が実frameには十分な境界で、共通余力の保守的な見積りによる誤欠測を防ぐ。
func TestOptionalBatchExactDayCapacity(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	root := t.TempDir()
	os.Chmod(root, 0700)
	site := domain.NewID()
	s, e := OpenOptionalStore(root, site, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	now := time.Now().UTC()
	at := domain.Time(now.UnixNano())
	makeRecord := func() OptionalRecord {
		r := optionalFixture()
		r.Site = site
		r.Received = at
		r.Finished = at + 100
		r.Until = at + domain.Time(OptionalRetention)
		return r
	}
	if e = s.Write(context.Background(), makeRecord()); e != nil {
		t.Fatal(e)
	}
	day, _ := strconv.ParseUint(now.Format("20060102"), 10, 64)
	path := filepath.Join(root, strconv.FormatUint(day, 10))
	var used int64
	files, e := os.ReadDir(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, file := range files {
		info, e := file.Info()
		if e != nil {
			t.Fatal(e)
		}
		used += info.Size()
	}
	info, e := os.Stat(filepath.Join(path, "control-000001.wal"))
	if e != nil {
		t.Fatal(e)
	}
	remaining := 2*(info.Size()-64) + 128
	filler := filepath.Join(path, "capacity-test")
	f, e := os.OpenFile(filler, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(MaxOptionalDayBytes - used - remaining); e != nil {
		t.Fatal(e)
	}
	f.Close()
	defer os.Remove(filler)
	records := []OptionalRecord{makeRecord(), makeRecord()}
	reservation, e := OptionalBatchReservation(records)
	if e != nil || reservation <= remaining {
		t.Fatal("fixture boundary", reservation, remaining, e)
	}
	for _, e := range s.WriteBatch(context.Background(), records) {
		if e != nil {
			t.Fatal("false capacity loss", e)
		}
	}
	if e = s.Write(context.Background(), makeRecord()); e == nil || s.journals[day].seq != 3 {
		t.Fatal("real capacity bound lost", e)
	}
}
