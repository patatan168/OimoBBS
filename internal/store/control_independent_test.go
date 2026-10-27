// 新規journal行の並行検証で、全件join・保存前拒否・一回同期・不明時の非公開を検査する。
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func independentControlFrame(t *testing.T, seq domain.U64, key string, value json.RawMessage) []byte {
	t.Helper()
	op := ControlOperation{Schema: 1, Seq: seq, ExpectedSeq: seq - 1, Actor: domain.Actor{Kind: "system", Reason: "test"}, Mutations: []Mutation{{Collection: "attempt", Key: key, Value: value}}, Result: ControlResult{Code: "saved", Targets: []string{}}}
	raw, err := json.Marshal(op)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := EncodeFrame(Frame{FirstSeq: uint64(seq), Records: []Record{{ID: domain.NewID(), JSON: raw}}})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestIndependentControlValidationBeforeWriteAndSync(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, failure := range []string{"none", "validate", "sync", "sequence", "existing", "duplicate", "null"} {
		t.Run(failure, func(t *testing.T) {
			header := Header{Kind: 8, Owner: domain.NewID(), Key: 20261023, Generation: 1}
			dir := filepath.Join(privateTemp(t), "journal")
			plain := func(string, string, json.RawMessage, json.RawMessage) error { return nil }
			log, err := CreateControl(dir, header, independentControlFrame(t, 1, "first", json.RawMessage(`{"n":1}`)), plain)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()
			before := log.State()
			stats := log.CommitStats()
			frames := make([][]byte, 4)
			for i := range frames {
				key := fmt.Sprintf("entry%d", i)
				value := json.RawMessage(`{"n":2}`)
				if i == 3 {
					switch failure {
					case "existing":
						key = "first"
					case "duplicate":
						key = "entry0"
					case "null":
						value = json.RawMessage(`null`)
					}
				}
				seq := domain.U64(i + 2)
				if failure == "sequence" && i == 3 {
					seq++
				}
				frames[i] = independentControlFrame(t, seq, key, value)
			}
			entered := make(chan struct{}, 4)
			release := make(chan struct{})
			var calls atomic.Int32
			rejected := errors.New("bad journal value")
			log.validator = func(_, key string, _, _ json.RawMessage) error {
				calls.Add(1)
				entered <- struct{}{}
				<-release
				if failure == "validate" && key == "entry2" {
					return rejected
				}
				return nil
			}
			if failure == "sync" {
				mock := &batchSyncWriter{faultWriter: &faultWriter{syncErr: errors.New("sync")}}
				log.writer = NewWriter(mock)
				stats = log.CommitStats()
			}
			done := make(chan CommitResult, 1)
			go func() { done <- log.AppendIndependentBatch(frames) }()
			if failure == "existing" || failure == "duplicate" || failure == "null" {
				result := <-done
				if result.Status != NotWritten || calls.Load() != 0 || log.CommitStats() != stats {
					t.Fatal("invalid independence reached validator/storage", result, calls.Load())
				}
				return
			}
			for range 4 {
				<-entered
			}
			if log.CommitStats() != stats || log.State().Seq != 1 {
				t.Error("wrote before all validators joined")
			}
			close(release)
			result := <-done
			if calls.Load() != 4 {
				t.Fatal("validator count", calls.Load())
			}
			if failure == "none" {
				if result.Status != Durable || log.State().Seq != 5 || log.CommitStats().Syncs-stats.Syncs != 1 {
					t.Fatal(result)
				}
				log.Close()
				reopened, err := OpenControl(dir, 8, header.Owner, header.Key, plain)
				if err != nil {
					t.Fatal(err)
				}
				defer reopened.Close()
				if reopened.State().Seq != 5 || len(reopened.State().Rows) != 5 {
					t.Fatal("independent replay")
				}
			} else if failure == "sync" {
				if result.Status != Unknown || log.State().Seq != 1 {
					t.Fatal("published uncertain batch", result)
				}
			} else if result.Status != NotWritten || log.CommitStats() != stats || log.State().Seq != 1 {
				t.Fatal("invalid batch reached disk", result)
			}
			if before.Seq != 1 || len(before.Rows) != 1 {
				t.Fatal("old snapshot mutated")
			}
		})
	}
}
