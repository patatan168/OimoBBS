// 逐次照合を既存の受理集合と比較し、対象外・callback失敗の境界を検証する。
package app

import (
	"errors"
	"reflect"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

func TestVisitAcceptedRecordsInRange(t *testing.T) {
	f := newRetirementFixture(t)
	journals := []*evidence.Journal{f.journal}
	expected, err := AcceptedRecords(journals)
	if err != nil {
		t.Fatal(err)
	}
	var actual []AcceptedEvidence
	match := func(owner domain.ID, _ domain.U64, _ domain.Time, _ domain.ID) bool { return owner == f.owner }
	if err = VisitAcceptedRecordsInRange(journals, match, func(row AcceptedEvidence) error { actual = append(actual, row); return nil }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatal("stream differs from accepted collection")
	}
	failed := errors.New("visitor stopped")
	if err = VisitAcceptedRecordsInRange(journals, match, func(AcceptedEvidence) error { return failed }); !errors.Is(err, failed) {
		t.Fatal("callback failure lost")
	}
	if err = VisitAcceptedRecordsInRange(journals, func(domain.ID, domain.U64, domain.Time, domain.ID) bool { return false }, func(AcceptedEvidence) error { t.Fatal("unexpected selected record"); return nil }); err != nil {
		t.Fatal(err)
	}
}
