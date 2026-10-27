// 正当署名の候補でも別予約の脱落や現在解除の差替えを保存前に拒否することを検査する。
package evidence

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

func TestCommitOptionalHoldRetirementRejectsSignedWrongRemoval(t *testing.T) {
	for _, change := range []string{"unrelated", "drop-live", "release"} {
		t.Run(change, func(t *testing.T) {
			s, _, b, entries, at := prepareOptionalRetirementFixture(t)
			second := b
			second.Case = domain.NewID()
			if err := s.ReserveOptionalHold(t.Context(), second, entries, at); err != nil {
				t.Fatal(err)
			}
			released, _, err := s.OptionalHoldReceipt(b.Case)
			if err != nil {
				t.Fatal(err)
			}
			at = time.Unix(0, int64(max(s.floor, s.holdIndex.payload.At))+1)
			candidate, err := s.PrepareOptionalHoldRetirement(t.Context(), released, domain.Hash{1}, domain.Hash{2}, at)
			if err != nil {
				t.Fatal(err)
			}
			candidate = wrongSignedOptionalRetirement(t, s, candidate, change)
			before := snapshotOptionalRetirementFiles(t, s)
			if err := s.CommitOptionalHoldRetirement(t.Context(), candidate, OptionalHoldRetirementReader, at, func(OptionalHoldRetirementCandidate) error {
				t.Fatal("invalid source candidate entered authorization")
				return nil
			}); err == nil {
				t.Fatal("signed wrong removal accepted")
			}
			if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
				t.Fatal("wrong removal changed files")
			}
		})
	}
}

func wrongSignedOptionalRetirement(t *testing.T, s *OptionalStore, candidate OptionalHoldRetirementCandidate, change string) OptionalHoldRetirementCandidate {
	t.Helper()
	raw, err := json.Marshal(candidate.Next)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.decodeOptionalHoldIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	switch change {
	case "unrelated":
		next.retirement.Case = domain.NewID()
	case "drop-live":
		next.payload.Cases = []domain.ID{}
	case "release":
		next.retirement.Release[0] ^= 1
	}
	body, err := marshalOptionalHoldIndexPayload(next.payload, next.retirement)
	if err != nil {
		t.Fatal(err)
	}
	candidate.Next, err = Seal(Source{next.payload.Owner, 0, uint64(next.payload.Sequence)}, s.site, "checkpoint", body, candidate.Previous.EventSHA, 10, s.key)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}
