// 明示的に独立したBuildのCPU分担・全終了待ちと、失敗時の無書込みを検証する。
package evidence

import (
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestConcurrentBuildJoinsBeforeSaving(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "accept", true: "reject"}[failure], func(t *testing.T) {
			j, _, _, _ := optionalJournalFixture(t)
			j.validate = testValidator
			defer j.Close()
			build := func(s Source) ([]byte, error) {
				return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
			}
			if _, r := j.Append(domain.NewID(), "attempt", 1, build); r.Status != store.Durable {
				t.Fatal(r)
			}
			before := j.CommitStats()
			entered := make(chan struct{}, 4)
			release := make(chan struct{})
			done := make(chan store.CommitResult, 1)
			var active atomic.Int32
			requests := make([]AppendRequest, 4)
			rejected := errors.New("build rejected")
			for i := range requests {
				requests[i] = AppendRequest{ID: domain.NewID(), Kind: "attempt", Committed: 1, Build: func(s Source) ([]byte, error) {
					active.Add(1)
					entered <- struct{}{}
					<-release
					active.Add(-1)
					if failure && i == 1 {
						return nil, rejected
					}
					return build(s)
				}}
			}
			go func() { _, r := j.AppendBatchConcurrentBuild(requests); done <- r }()
			for range 4 {
				select {
				case <-entered:
				case <-t.Context().Done():
					t.Fatal("independent builds did not start")
				}
			}
			if j.CommitStats() != before {
				t.Fatal("saved before all builds completed")
			}
			close(release)
			result := <-done
			if active.Load() != 0 {
				t.Fatal("returned before join")
			}
			if failure {
				if result.Status != store.NotWritten || !errors.Is(result.Err, rejected) || j.CommitStats() != before || len(j.entries) != 1 {
					t.Fatal(result)
				}
			} else {
				if result.Status != store.Durable || j.CommitStats().Syncs-before.Syncs != 1 || len(j.entries) != 5 {
					t.Fatal(result)
				}
				for i, e := range j.entries {
					var payload testPayload
					if err := json.Unmarshal(e.Payload, &payload); err != nil || uint64(payload.Seq) != uint64(i+1) {
						t.Fatal("sequence", err, payload.Seq)
					}
				}
			}
		})
	}
}

// source検査を構築workerへ移しても、後続の構築失敗を先に返す従来の優先順を保つ。
func TestConcurrentBuildPreservesFailurePriority(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	j, _, _, _ := optionalJournalFixture(t)
	j.validate = testValidator
	defer j.Close()
	build := func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
	}
	if _, result := j.Append(domain.NewID(), "attempt", 1, build); result.Status != store.Durable {
		t.Fatal(result)
	}
	before := j.CommitStats()
	rejected := errors.New("later build rejected")
	requests := []AppendRequest{
		{ID: domain.NewID(), Kind: "attempt", Committed: 1, Build: func(s Source) ([]byte, error) {
			s.Seq++
			return build(s)
		}},
		{ID: domain.NewID(), Kind: "attempt", Committed: 1, Build: func(Source) ([]byte, error) { return nil, rejected }},
	}
	if _, result := j.AppendBatchConcurrentBuild(requests); result.Status != store.NotWritten || !errors.Is(result.Err, rejected) || j.CommitStats() != before || len(j.entries) != 1 {
		t.Fatal("failure priority or persistence changed", result)
	}
	requests[1].Build = build
	if _, result := j.AppendBatchConcurrentBuild(requests); result.Status != store.NotWritten || result.Err == nil || j.CommitStats() != before || len(j.entries) != 1 {
		t.Fatal("invalid source accepted", result)
	}
}
