// Package app は接続記録と投稿の耐久確定、公開順を仲介する。
package app

import (
	"context"
	"errors"
	"oimobbs/internal/store"
)

// CommitSteps は同じ板ワーカーが直列実行する保存境界。Publishは失敗しない参照交換のみ。
type CommitSteps struct {
	Proposal           func() store.CommitResult
	Thread             func() store.CommitResult
	Decision           func() store.CommitResult
	Publish            func()
	StopWriter         func()
	ReleaseReservation func()
}

// Commit はproposal→thread→acceptedのSync後だけ公開する。
// proposalを開始した後のcontext取消は無視し、保存結果を確定させる。
func Commit(ctx context.Context, s CommitSteps) store.CommitResult {
	if s.Proposal == nil || s.Thread == nil || s.Decision == nil || s.Publish == nil || s.StopWriter == nil || s.ReleaseReservation == nil {
		return store.CommitResult{Status: store.NotWritten, Err: errors.New("incomplete commit steps")}
	}
	if e := ctx.Err(); e != nil {
		s.ReleaseReservation()
		return store.CommitResult{Status: store.NotWritten, Err: e}
	}
	for i, step := range []func() store.CommitResult{s.Proposal, s.Thread, s.Decision} {
		r := step()
		if r.Status == store.Durable {
			continue
		}
		if r.Status == store.Unknown || i > 0 {
			s.StopWriter()
			r.Status = store.Unknown
		} else {
			s.ReleaseReservation()
		}
		return r
	}
	s.Publish()
	return store.CommitResult{Status: store.Durable}
}
