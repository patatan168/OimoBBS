// 確定途中の各停止点で公開されず、取消境界を越えた処理は完了することを検査する。
package app

import (
	"context"
	"errors"
	"oimobbs/internal/store"
	"reflect"
	"testing"
)

func TestCommitStops(t *testing.T) {
	for fail := -1; fail < 3; fail++ {
		var calls []string
		stopped, released := false, false
		step := func(n int, name string) func() store.CommitResult {
			return func() store.CommitResult {
				calls = append(calls, name)
				if n == fail {
					return store.CommitResult{Status: store.Unknown, Err: errors.New("fault")}
				}
				return store.CommitResult{Status: store.Durable}
			}
		}
		r := Commit(context.Background(), CommitSteps{step(0, "proposal"), step(1, "thread"), step(2, "decision"), func() { calls = append(calls, "publish") }, func() { stopped = true }, func() { released = true }})
		if fail < 0 {
			if r.Status != store.Durable || !reflect.DeepEqual(calls, []string{"proposal", "thread", "decision", "publish"}) {
				t.Fatal(calls, r)
			}
		} else if r.Status != store.Unknown || !stopped || released || len(calls) != fail+1 {
			t.Fatal(calls, r, stopped, released)
		}
	}
}
func TestCancellationBoundary(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	published := false
	ok := func() store.CommitResult { return store.CommitResult{Status: store.Durable} }
	r := Commit(ctx, CommitSteps{func() store.CommitResult { cancel(); return ok() }, ok, ok, func() { published = true }, func() { t.Fatal("stopped") }, func() { t.Fatal("released") }})
	if r.Status != store.Durable || !published {
		t.Fatal(r)
	}
}
