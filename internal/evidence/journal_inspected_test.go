// 署名検査・起動境界・不完全末尾の拒否が、保存元を変えず一回の読込みで成立するか検査する。
package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestJournalInspectedBoundaryBeforeRecovery(t *testing.T) {
	for _, mode := range []string{"accept", "boundary", "partial", "payload"} {
		t.Run(mode, func(t *testing.T) {
			j, key, owner, path := optionalJournalFixture(t)
			j.validate = testValidator
			for range 8 {
				_, saved := j.Append(domain.NewID(), "attempt", 1, func(s Source) ([]byte, error) {
					return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
				})
				if saved.Status != store.Durable {
					t.Fatal(saved)
				}
			}
			if err := j.Close(); err != nil {
				t.Fatal(err)
			}
			wal := filepath.Join(path, "control-000001.wal")
			if mode == "partial" {
				f, err := os.OpenFile(wal, os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte("partial"))
				f.Close()
				if err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(wal)
			if err != nil {
				t.Fatal(err)
			}
			rejected := errors.New("boundary rejected")
			var calls atomic.Int32
			inspected := false
			opened, err := OpenJournalInspected(path, owner, 20261005, 10, key, func(kind string, raw []byte) error {
				calls.Add(1)
				if mode == "payload" {
					return rejected
				}
				return testValidator(kind, raw)
			}, func(info JournalInspection) error {
				inspected = true
				if info.Sequence != 8 {
					t.Errorf("wrong sequence %d", info.Sequence)
				}
				if mode == "boundary" {
					return rejected
				}
				return nil
			})
			if opened != nil {
				defer opened.Close()
			}
			if mode == "accept" {
				if err != nil || !inspected || calls.Load() != 8 || len(opened.Entries()) != 8 {
					t.Fatal("one read not shared", err, inspected, calls.Load())
				}
			} else {
				if err == nil || opened != nil {
					t.Fatal("invalid recovery accepted")
				}
				if mode == "partial" && !errors.Is(err, store.ErrIncomplete) {
					t.Fatal(err)
				}
				if mode == "payload" && inspected {
					t.Fatal("boundary called before payload validation")
				}
			}
			after, readErr := os.ReadFile(wal)
			if readErr != nil || !bytes.Equal(before, after) {
				t.Fatal("source modified before boundary", readErr)
			}
		})
	}
}

// 保存block内の検査が複数CPUで走り、全worker終了前に境界検査へ進まないことを同期障壁で確認する。
func TestJournalInspectedParallelValuesJoin(t *testing.T) {
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
	if _, saved := j.AppendBatchConcurrent(requests); saved.Status != store.Durable {
		t.Fatal(saved)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	done := make(chan error, 1)
	var active, calls atomic.Int32
	go func() {
		opened, err := OpenJournalInspected(path, owner, 20261005, 10, key, func(kind string, raw []byte) error {
			var payload testPayload
			if err := json.Unmarshal(raw, &payload); err != nil {
				return err
			}
			calls.Add(1)
			if payload.Seq >= 2 && payload.Seq <= 5 {
				active.Add(1)
				entered <- struct{}{}
				<-release
				active.Add(-1)
			}
			return testValidator(kind, raw)
		}, func(info JournalInspection) error {
			if active.Load() != 0 || info.Sequence != 9 {
				return errors.New("boundary before join")
			}
			return nil
		})
		if opened != nil {
			err = errors.Join(err, opened.Close())
		}
		done <- err
	}()
	for range 4 {
		select {
		case <-entered:
		case <-t.Context().Done():
			t.Fatal("parallel validation did not start")
		}
	}
	close(release)
	if err := <-done; err != nil || calls.Load() != 9 {
		t.Fatal("join/count", err, calls.Load())
	}
}
