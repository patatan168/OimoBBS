// snapshot後のdelta走査・cursor世代束縛・失敗位置からの再開を検証する。
package store

import (
	"context"
	"errors"
	"testing"
)

func TestControlDeltaCursorAndBounds(t *testing.T) {
	log, _ := switchFixture(t)
	ctx := context.Background()
	var old HistoryCursor
	budget := HistoryBudget{1 << 20, 100}
	visit := func(Record, ControlOperation) error { return nil }
	if err := log.VisitDeltaFrom(ctx, &old, &budget, visit); err != nil {
		t.Fatal(err)
	}
	if result := log.SwitchSnapshot(switchBytes(t, log, 6)); result.Status != Durable {
		t.Fatal(result)
	}
	budget = HistoryBudget{1 << 20, 100}
	if err := log.VisitDeltaFrom(ctx, &old, &budget, visit); !errors.Is(err, ErrCorrupt) {
		t.Fatal("old generation cursor", err)
	}
	if err := log.VisitCommitted(ctx, &budget, visit); !errors.Is(err, ErrHistoryCompacted) {
		t.Fatal(err)
	}
	var cursor HistoryCursor
	budget = HistoryBudget{63, 10}
	if err := log.VisitDeltaFrom(ctx, &cursor, &budget, visit); !errors.Is(err, ErrHistoryBudget) {
		t.Fatal(err)
	}
	budget = HistoryBudget{64, 0}
	if err := log.VisitDeltaFrom(ctx, &cursor, &budget, func(Record, ControlOperation) error { t.Fatal("empty delta visited"); return nil }); err != nil {
		t.Fatal(err)
	}
	for _, seq := range []uint64{3, 4} {
		if log.Append(switchFrame(seq)).Status != Durable {
			t.Fatal("append")
		}
	}
	budget = HistoryBudget{1 << 20, 1}
	var got []uint64
	err := log.VisitDeltaFrom(ctx, &cursor, &budget, func(_ Record, op ControlOperation) error { got = append(got, uint64(op.Seq)); return nil })
	if !errors.Is(err, ErrHistoryBudget) || len(got) != 1 || got[0] != 3 {
		t.Fatal(got, err)
	}
	injected := errors.New("sink unavailable")
	budget = HistoryBudget{1 << 20, 100}
	if err = log.VisitDeltaFrom(ctx, &cursor, &budget, func(Record, ControlOperation) error { return injected }); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	budget = HistoryBudget{1 << 20, 100}
	if err = log.VisitDeltaFrom(ctx, &cursor, &budget, func(_ Record, op ControlOperation) error {
		if op.Seq != 4 {
			t.Fatal(op.Seq)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	budget = HistoryBudget{}
	if err = log.VisitDeltaFrom(ctx, &cursor, &budget, visit); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err = log.VisitDeltaFrom(canceled, &cursor, &budget, visit); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// Sync失敗で完全frameが残っても、稼働中の確定seqには含めない。
	log.writer = NewWriter(historyFailedSync{log.file})
	if log.Append(switchFrame(5)).Status != Unknown {
		t.Fatal("expected sync failure")
	}
	if err = log.VisitDeltaFrom(ctx, &cursor, &budget, func(Record, ControlOperation) error { t.Fatal("unknown frame"); return nil }); err != nil {
		t.Fatal(err)
	}
}
