// 検査済み登録の起動位置選択が後続予約を過去候補へ戻さず、未開始競合を拒否することを検査する。
package bootstrap

import (
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"testing"
)

func TestOptionalRetirementStartupSelectionPreservesAdvancedIndex(t *testing.T) {
	id := domain.NewID()
	hash := domain.Hash{1}
	row := checkedOptionalRetirement{
		Registration: optionalHoldRetirementRegistration{Previous: evidence.Event{EventSHA: domain.Hash{2}}, Next: evidence.Event{EventSHA: domain.Hash{3}}},
		Description:  evidence.OptionalHoldRetirementDescription{Case: id, Sequence: 3},
	}
	rows := map[domain.Hash]checkedOptionalRetirement{hash: row}
	for _, seq := range []domain.U64{2, 3, 4, 1000} {
		index := evidence.OptionalHoldIndexDescription{Sequence: seq, SHA: domain.Hash{3}, Cases: []domain.ID{}}
		if seq == 2 {
			index.SHA = domain.Hash{2}
			index.Cases = []domain.ID{id}
		}
		selected, err := selectOptionalRetirementStartup(index, nil, rows)
		if err != nil {
			t.Fatal(seq, err)
		}
		if (selected != nil) != (seq <= 3) {
			t.Fatal("advanced index selected past candidate", seq)
		}
	}
	bad := evidence.OptionalHoldIndexDescription{Sequence: 3, SHA: domain.Hash{4}, Cases: []domain.ID{}}
	if _, err := selectOptionalRetirementStartup(bad, nil, rows); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("same sequence changed index accepted", err)
	}
	assertOptionalRetirementConflictingStartup(t, rows, row, id)
}

func assertOptionalRetirementConflictingStartup(t *testing.T, rows map[domain.Hash]checkedOptionalRetirement, row checkedOptionalRetirement, id domain.ID) {
	t.Helper()
	other := row
	other.Description.Case = domain.NewID()
	rows[domain.Hash{5}] = other
	index := evidence.OptionalHoldIndexDescription{Sequence: 2, SHA: row.Registration.Previous.EventSHA, Cases: []domain.ID{id, other.Description.Case}}
	if _, err := selectOptionalRetirementStartup(index, nil, rows); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("two competing registrations accepted", err)
	}
}
