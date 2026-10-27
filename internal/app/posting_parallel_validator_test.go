// 外部検証器の既定の直列性と、明示契約した検証器の並行実行を確認する。
package app

import (
	"context"
	"oimobbs/internal/parallel"
	"oimobbs/internal/store"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestPostingCaptureConcurrencyContract(t *testing.T) {
	previous := runtime.GOMAXPROCS(4)
	defer runtime.GOMAXPROCS(previous)
	p, j, frame, now, _, _ := newPostingTest(t)
	if result := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); result.Status != store.Durable {
		t.Fatal(result)
	}
	var raw []byte
	for _, entry := range j.Entries() {
		if entry.Event.Kind == "evidence_proposal" {
			raw = entry.Payload
			break
		}
	}
	if raw == nil {
		t.Fatal("missing proposal")
	}
	for _, concurrent := range []bool{false, true} {
		t.Run(map[bool]string{false: "serialized", true: "parallel"}[concurrent], func(t *testing.T) {
			var active, peak atomic.Int32
			entered := make(chan struct{}, 4)
			release := make(chan struct{})
			check := func([]byte) error {
				n := active.Add(1)
				for old := peak.Load(); n > old; old = peak.Load() {
					if peak.CompareAndSwap(old, n) {
						break
					}
				}
				if concurrent {
					entered <- struct{}{}
					<-release
				} else {
					runtime.Gosched()
				}
				active.Add(-1)
				return nil
			}
			validate := PostingValidator(check)
			if concurrent {
				validate = PostingValidatorConcurrent(check)
			}
			if concurrent {
				go func() {
					for i := 0; i < 4; i++ {
						<-entered
					}
					close(release)
				}()
			}
			errs := make([]error, 4)
			parallel.CPU(4, func(i int) { errs[i] = validate("evidence_proposal", raw) })
			for _, err := range errs {
				if err != nil {
					t.Fatal(err)
				}
			}
			want := int32(1)
			if concurrent {
				want = 4
			}
			if peak.Load() != want || active.Load() != 0 {
				t.Fatal("capture concurrency", peak.Load(), active.Load())
			}
		})
	}
}
