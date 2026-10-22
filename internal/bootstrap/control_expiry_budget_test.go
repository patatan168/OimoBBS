// 監査走査の有界な中断から再開し、併記された保存失敗を延期しないことを検証する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	"oimobbs/internal/store"
)

func TestControlExpiryAuditBudgetDeferral(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false}, {store.ErrHistoryBudget, true},
		{fmt.Errorf("audit: %w", store.ErrHistoryBudget), true},
		{errors.Join(store.ErrHistoryBudget, store.ErrHistoryBudget), true},
		{errors.Join(store.ErrHistoryBudget, io.ErrShortWrite), false},
		{errors.Join(store.ErrHistoryBudget, store.ErrCorrupt), false},
		{errors.Join(store.ErrHistoryBudget, context.Canceled), false},
		{io.ErrShortWrite, false},
	} {
		if got := onlyAuditHistoryBudget(tc.err); got != tc.want {
			t.Fatalf("%v: deferred=%v", tc.err, got)
		}
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	budget := store.HistoryBudget{Bytes: 1 << 20, Frames: 1}
	err := catchUpAuditFixture(repo, context.Background(), &budget)
	if !onlyAuditHistoryBudget(err) {
		t.Fatalf("expected resumable budget exhaustion: %v", err)
	}
	budget = store.HistoryBudget{Bytes: 1 << 20, Frames: 100}
	if err = catchUpAuditFixture(repo, context.Background(), &budget); err != nil {
		t.Fatal("resume", err)
	}
	if repo.auditIndex.count != 1 {
		t.Fatal("lost or duplicate audit entry", repo.auditIndex.count)
	}
	budget = store.HistoryBudget{}
	if err = catchUpAuditFixture(repo, context.Background(), &budget); err != nil {
		t.Fatal("completed cursor reread history", err)
	}
}
