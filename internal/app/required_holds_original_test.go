// 解除後の初回予約参照を実署名履歴から再起動後にも取り出せることを確認する。
package app

import (
	"oimobbs/internal/evidence"
	"testing"
)

func TestRequiredOriginalReceiptSurvivesReleaseAndRestart(t *testing.T) {
	f, h, path, b, rows, now := requiredHoldsFixture(t)
	original, e := h.Reserve(b, rows, map[uint64]*evidence.Journal{20231114: f.journal}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Release(original, now); e != nil {
		t.Fatal(e)
	}
	if e = h.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenRequiredOriginalHolds(path, f.owner, 10, f.key, true)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	before := retirementFiles(t, path)
	got, found, e := reopened.OriginalReceipt(b.Case)
	if e != nil || !found || !sameRequiredHoldReceipt(got, original) {
		t.Fatal(got, found, e)
	}
	got.Postings[0].Proposal.Sequence++
	again, _, e := reopened.OriginalReceipt(b.Case)
	if e != nil || !sameRequiredHoldReceipt(again, original) {
		t.Fatal("original receipt aliases state", e)
	}
	after := retirementFiles(t, path)
	for name, raw := range before {
		if string(raw) != string(after[name]) {
			t.Fatal("lookup mutated history")
		}
	}
}
