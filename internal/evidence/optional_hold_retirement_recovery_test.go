// 回収対応索引でも通常の予約解除の保存停止が従来のreloadで復旧できることを検査する。
package evidence

import (
	"errors"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestOptionalRetirementIndexPreservesOrdinaryHoldRecovery(t *testing.T) {
	s, candidate, b, entries, at := prepareOptionalRetirementFixture(t)
	if err := s.CommitOptionalHoldRetirement(t.Context(), candidate, OptionalHoldRetirementReader, at, allowOptionalRetirement); err != nil {
		t.Fatal(err)
	}
	b.Case = domain.NewID()
	if err := s.ReserveOptionalHold(t.Context(), b, entries, at); err != nil {
		t.Fatal(err)
	}
	at = time.Unix(0, int64(max(s.floor, s.holdIndex.payload.At))+1)
	injected := errors.New("ordinary release stopped after retirement")
	s.checkpoint = func(point string) error {
		if point == "hold:sync" {
			return injected
		}
		return nil
	}
	if err := s.ReleaseOptionalHold(t.Context(), b.Case, 2, at); !errors.Is(err, injected) {
		t.Fatal("release stop", err)
	}
	s.checkpoint = nil
	if err := s.ReloadOptionalHolds(); err != nil {
		t.Fatal("ordinary release recovery blocked by v2", err)
	}
	released, exists, err := s.OptionalHoldReceipt(b.Case)
	if err != nil || !exists || released.State != "released" {
		t.Fatal("release not recovered", err)
	}
}
