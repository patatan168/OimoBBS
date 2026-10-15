// 索引回収候補の現在解除照合・署名束縛・非変更と不正入力の拒否を検査する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func TestPrepareOptionalHoldRetirementBindsCurrentReleasedSource(t *testing.T) {
	s, _, b, entries, now := optionalHoldFixture(t)
	if err := s.ReserveOptionalHold(t.Context(), b, entries, now); err != nil {
		t.Fatal(err)
	}
	active, _, err := s.OptionalHoldReceipt(b.Case)
	if err != nil {
		t.Fatal(err)
	}
	second := b
	second.Case = domain.NewID()
	if err := s.ReserveOptionalHold(t.Context(), second, entries, now); err != nil {
		t.Fatal(err)
	}
	if err := s.ReleaseOptionalHold(t.Context(), b.Case, 2, now); err != nil {
		t.Fatal(err)
	}
	released, _, err := s.OptionalHoldReceipt(b.Case)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(0, int64(max(s.floor, s.holdIndex.payload.At, released.At))+1)
	fingerprint, registration := domain.Hash{1}, domain.Hash{2}
	before := snapshotOptionalRetirementFiles(t, s)
	candidate, err := s.PrepareOptionalHoldRetirement(t.Context(), released, fingerprint, registration, at)
	if err != nil {
		t.Fatal(err)
	}
	assertOptionalRetirementCandidate(t, s, candidate, released, second.Case, fingerprint, registration, at)
	assertOptionalRetirementPrepareRejects(t, s, released, active, fingerprint, registration, at)
	if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
		t.Fatal("preparation changed durable source")
	}
	rows, err := s.OptionalHoldReceipts()
	if err != nil || len(rows) != 2 {
		t.Fatal("preparation freed a slot", len(rows), err)
	}
}

func assertOptionalRetirementCandidate(t *testing.T, s *OptionalStore, candidate OptionalHoldRetirementCandidate, released OptionalHoldReceipt, remaining domain.ID, fingerprint, registration domain.Hash, at time.Time) {
	t.Helper()
	if !equalOptionalHoldBytes(candidate.Previous, s.holdIndex.event) {
		t.Fatal("candidate previous is not current index")
	}
	body, err := Verify(Source{optionalHoldIndexOwner(s.site), 0, uint64(s.holdIndex.payload.Sequence) + 1}, candidate.Next, candidate.Previous.EventSHA, 10, s.key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal("candidate signature", err)
	}
	var p optionalHoldRetirementIndexPayload
	if err := strictjson.Decode(body, &p); err != nil {
		t.Fatal(err)
	}
	expected := optionalHoldIndexRetirement{released.Binding.Case, fingerprint, released.SHA, registration}
	if p.Schema != "optional-http-hold-index-v2" || p.Site != s.site || p.At != domain.Time(at.UnixNano()) || !reflect.DeepEqual(p.Cases, []domain.ID{remaining}) || p.Retirement == nil || *p.Retirement != expected {
		t.Fatal("candidate not bound to single source retirement")
	}
	assertOptionalRetirementCandidateCodec(t, s, candidate.Next)
}

func assertOptionalRetirementCandidateCodec(t *testing.T, s *OptionalStore, next Event) {
	t.Helper()
	raw, err := json.Marshal(next)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.decodeOptionalHoldIndex(raw); err != nil {
		t.Fatal("v2 candidate signature/shape rejected", err)
	}
}

func assertOptionalRetirementPrepareRejects(t *testing.T, s *OptionalStore, released, active OptionalHoldReceipt, fingerprint, registration domain.Hash, at time.Time) {
	t.Helper()
	changedScope := released
	changedScope.Binding.Board = domain.NewID()
	changedSequence := released
	changedSequence.Sequence++
	for _, reference := range []OptionalHoldReceipt{active, changedOptionalRetirementReceipt(released), changedScope, changedSequence} {
		if _, err := s.PrepareOptionalHoldRetirement(t.Context(), reference, fingerprint, registration, at); !errors.Is(err, store.ErrCorrupt) {
			t.Fatal("active or changed release accepted", err)
		}
	}
	for _, binding := range [][2]domain.Hash{{{}, registration}, {fingerprint, {}}} {
		if _, err := s.PrepareOptionalHoldRetirement(t.Context(), released, binding[0], binding[1], at); !errors.Is(err, store.ErrCorrupt) {
			t.Fatal("missing registration binding accepted", err)
		}
	}
	if _, err := s.PrepareOptionalHoldRetirement(t.Context(), released, fingerprint, registration, at.Add(-time.Second)); !errors.Is(err, ErrRetirementClock) {
		t.Fatal("clock rollback accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.PrepareOptionalHoldRetirement(ctx, released, fingerprint, registration, at); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preparation accepted", err)
	}
}

func changedOptionalRetirementReceipt(reference OptionalHoldReceipt) OptionalHoldReceipt {
	reference.SHA[0] ^= 1
	return reference
}

// snapshotOptionalRetirementFiles は候補構成が全予約fileのbytesを変えないことを比較する。
func snapshotOptionalRetirementFiles(t *testing.T, s *OptionalStore) map[string]string {
	t.Helper()
	dir := filepath.Join(s.root, optionalHoldsDir)
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[string]string, len(files))
	for _, file := range files {
		raw, err := os.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[file.Name()] = string(raw)
	}
	return result
}

func TestPrepareOptionalHoldRetirementRejectsDiskRollbackAndPending(t *testing.T) {
	for _, mode := range []string{"rollback", "pending", "missing"} {
		t.Run(mode, func(t *testing.T) {
			s, _, b, entries, now := optionalHoldFixture(t)
			if err := s.ReserveOptionalHold(t.Context(), b, entries, now); err != nil {
				t.Fatal(err)
			}
			path := s.holdFile(b.Case)
			active, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.ReleaseOptionalHold(t.Context(), b.Case, 2, now); err != nil {
				t.Fatal(err)
			}
			released, _, err := s.OptionalHoldReceipt(b.Case)
			if err != nil {
				t.Fatal(err)
			}
			alterOptionalRetirementDisk(t, path, active, mode)
			before := snapshotOptionalRetirementFiles(t, s)
			at := time.Unix(0, int64(max(s.floor, s.holdIndex.payload.At))+1)
			if _, err := s.PrepareOptionalHoldRetirement(t.Context(), released, domain.Hash{1}, domain.Hash{2}, at); err == nil {
				t.Fatal("invalid disk state accepted")
			}
			if !reflect.DeepEqual(before, snapshotOptionalRetirementFiles(t, s)) {
				t.Fatal("preparation repaired source")
			}
		})
	}
}

func alterOptionalRetirementDisk(t *testing.T, path string, active []byte, mode string) {
	t.Helper()
	var err error
	switch mode {
	case "rollback":
		err = os.WriteFile(path, active, 0600)
	case "pending":
		err = os.WriteFile(path+".pending", active, 0600)
	case "missing":
		err = os.Remove(path)
	}
	if err != nil {
		t.Fatal(err)
	}
}
