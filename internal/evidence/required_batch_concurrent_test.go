// 並行payload検査のCPU枠・元byte所有権と、検査失敗時の無書込みを確認する。
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func TestConcurrentBatchValidationAndRecovery(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	j, key, owner, path := optionalJournalFixture(t)
	j.validate = testValidator
	build := func(src Source) ([]byte, error) {
		return json.Marshal(testPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), "private"})
	}
	if _, result := j.Append(domain.NewID(), "attempt", 1, build); result.Status != store.Durable {
		t.Fatal(result)
	}
	before := j.CommitStats()
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var calls, active, peak atomic.Int32
	j.validate = func(kind string, raw []byte) error {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		defer active.Add(-1)
		if calls.Add(1) <= 4 {
			entered <- struct{}{}
			<-release
		}
		return testValidator(kind, raw)
	}
	requests := make([]AppendRequest, 8)
	// Buildが同じ作業配列を返しても、検査対象と保存対象の元byteを一致させる。
	var buffer []byte
	for i := range requests {
		requests[i] = AppendRequest{domain.NewID(), "attempt", 1, func(src Source) ([]byte, error) {
			raw, err := build(src)
			buffer = append(buffer[:0], raw...)
			return buffer, err
		}}
	}
	done := make(chan store.CommitResult, 1)
	go func() { _, result := j.AppendBatchConcurrent(requests); done <- result }()
	for range 4 {
		<-entered
	}
	close(release)
	if result := <-done; result.Status != store.Durable {
		t.Fatal(result)
	}
	if peak.Load() != 4 || calls.Load() != 8 || j.CommitStats().Syncs-before.Syncs != 1 || j.preparedPayloads != nil {
		t.Fatal("並行枠・検査回数・同期境界", peak.Load(), calls.Load(), j.CommitStats())
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(path, owner, 20261005, 10, key, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	entries := reopened.Entries()
	if len(entries) != 9 {
		t.Fatal(len(entries))
	}
	for i, entry := range entries {
		var payload testPayload
		if err := json.Unmarshal(entry.Payload, &payload); err != nil || uint64(payload.Seq) != uint64(i+1) {
			t.Fatal("連番または元byte", i, err)
		}
		if i > 0 && entry.Event.PreviousSHA != entries[i-1].Event.EventSHA {
			t.Fatal("署名連鎖")
		}
	}
}

func TestConcurrentBatchFailureDoesNotWrite(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	j, _, _, _ := optionalJournalFixture(t)
	j.validate = testValidator
	defer j.Close()
	build := func(src Source) ([]byte, error) {
		return json.Marshal(testPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), "private"})
	}
	if _, result := j.Append(domain.NewID(), "attempt", 1, build); result.Status != store.Durable {
		t.Fatal(result)
	}
	rejected := errors.New("検査失敗")
	j.validate = func(kind string, raw []byte) error {
		if err := testValidator(kind, raw); err != nil {
			return err
		}
		var payload testPayload
		if err := json.Unmarshal(raw, &payload); err != nil {
			return err
		}
		if payload.Seq == 4 {
			return rejected
		}
		return nil
	}
	before := j.CommitStats()
	requests := make([]AppendRequest, 8)
	for i := range requests {
		requests[i] = AppendRequest{domain.NewID(), "attempt", 1, build}
	}
	if _, result := j.AppendBatchConcurrent(requests); result.Status != store.NotWritten || !errors.Is(result.Err, rejected) || j.CommitStats() != before || len(j.Entries()) != 1 || j.preparedPayloads != nil {
		t.Fatal("検査失敗で保存が始まった", result)
	}
	requests[7].ID = requests[0].ID
	if _, result := j.AppendBatchConcurrent(requests); result.Status != store.NotWritten || j.CommitStats() != before {
		t.Fatal("重複ID", result)
	}
}

func BenchmarkBatchPayloadValidation(b *testing.B) {
	owner := domain.NewID()
	j := &Journal{owner: owner, day: 20261005, ids: map[domain.ID]bool{}, validate: testValidator}
	requests := make([]AppendRequest, 64)
	text := strings.Repeat("日本語の本文。", 100)
	for i := range requests {
		requests[i] = AppendRequest{domain.NewID(), "attempt", 1, func(src Source) ([]byte, error) {
			return json.Marshal(testPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), text})
		}}
	}
	b.Run("serial", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			retained := make([][]byte, len(requests))
			for i, request := range requests {
				raw, err := request.Build(Source{owner, j.day, uint64(i + 1)})
				if err == nil {
					err = j.validatePayload(request.Kind, raw)
				}
				if err != nil {
					b.Fatal(err)
				}
				retained[i] = bytes.Clone(raw)
			}
			runtime.KeepAlive(retained)
		}
	})
	b.Run("concurrent", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := j.prepareConcurrentPayloads(requests); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// 不正に大きいbuilderの出力を全件複製してから拒否しない。
func TestConcurrentPayloadMemoryBound(t *testing.T) {
	for _, tc := range []struct{ size, count int }{{(512 << 10) + 1, 4}, {512 << 10, 17}} {
		body := make([]byte, tc.size)
		requests := make([]AppendRequest, tc.count)
		for i := range requests {
			requests[i] = AppendRequest{domain.NewID(), "attempt", 1, func(Source) ([]byte, error) { return body, nil }}
		}
		var calls int
		j := &Journal{owner: domain.NewID(), day: 20261005, ids: map[domain.ID]bool{}, validate: func(string, []byte) error { calls++; return nil }}
		if payloads, err := j.prepareConcurrentPayloads(requests); err == nil || payloads != nil || calls != 0 {
			t.Fatal("符号化不能なサイズを検査へ渡した", tc, err, calls)
		}
	}
}
