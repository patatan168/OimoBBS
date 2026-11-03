// 並行起動でも保存済みの署名・順序・本文検査と追記後の再読込みが維持されることを検査する。
package evidence

import (
	"context"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestJournalConcurrentRecoveryAndRejection(t *testing.T) {
	j, key, owner, path := optionalJournalFixture(t)
	j.validate = testValidator
	build := func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
	}
	if _, saved := j.Append(domain.NewID(), "attempt", 1, build); saved.Status != store.Durable {
		t.Fatal(saved)
	}
	for range 2 {
		requests := make([]AppendRequest, 64)
		for i := range requests {
			requests[i] = AppendRequest{domain.NewID(), "attempt", 1, build}
		}
		if _, saved := j.AppendBatch(requests); saved.Status != store.Durable {
			t.Fatal(saved)
		}
	}
	want := j.Entries()
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	opened, err := OpenJournalConcurrent(path, owner, 20261005, 10, key, func(kind string, raw []byte) error {
		calls.Add(1)
		return testValidator(kind, raw)
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened.Entries(), want) || calls.Load() != 129 {
		t.Fatal("parallel recovery changed entries or skipped validation", calls.Load())
	}
	if _, saved := opened.Append(domain.NewID(), "attempt", 1, build); saved.Status != store.Durable {
		t.Fatal(saved)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	serial, err := OpenJournal(path, owner, 20261005, 10, key, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	if len(serial.Entries()) != 130 {
		t.Fatal("appended entry did not survive reopen")
	}
	serial.Close()
	rejected := errors.New("payload rejected")
	if opened, err := OpenJournalConcurrent(path, owner, 20261005, 10, key, func(string, []byte) error { return rejected }); err == nil || opened != nil {
		t.Fatal("invalid payload accepted", err)
	}
	wrong := append([]byte(nil), key...)
	wrong[0] ^= 1
	wrong[32] ^= 1
	if opened, err := OpenJournalConcurrent(path, owner, 20261005, 10, wrong, testValidator); err == nil || opened != nil {
		t.Fatal("wrong signing key accepted", err)
	}
}

func TestJournalConcurrentValuesJoin(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	j, key, owner, path := optionalJournalFixture(t)
	j.validate = testValidator
	build := func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
	}
	if _, saved := j.Append(domain.NewID(), "attempt", 1, build); saved.Status != store.Durable {
		t.Fatal(saved)
	}
	requests := make([]AppendRequest, 8)
	for i := range requests {
		requests[i] = AppendRequest{domain.NewID(), "attempt", 1, build}
	}
	if _, saved := j.AppendBatch(requests); saved.Status != store.Durable {
		t.Fatal(saved)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}, 4), make(chan struct{})
	done := make(chan error, 1)
	var active atomic.Int32
	go func() {
		opened, err := OpenJournalConcurrent(path, owner, 20261005, 10, key, func(kind string, raw []byte) error {
			var payload testPayload
			if err := json.Unmarshal(raw, &payload); err != nil {
				return err
			}
			if payload.Seq >= 2 && payload.Seq <= 5 {
				active.Add(1)
				entered <- struct{}{}
				<-release
				active.Add(-1)
			}
			return testValidator(kind, raw)
		})
		if opened != nil {
			if active.Load() != 0 || len(opened.Entries()) != 9 {
				err = errors.New("recovery returned before validators joined")
			}
			err = errors.Join(err, opened.Close())
		}
		done <- err
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for range 4 {
		select {
		case <-entered:
		case <-ctx.Done():
			close(release)
			t.Fatal("concurrent validation did not start")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
