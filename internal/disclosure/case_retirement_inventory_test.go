// 実制御履歴・旧保存世代を固定一覧へ含め、未知/別所有者/変更候補を非変更で拒否する。
package disclosure

import (
	"context"
	"crypto/sha256"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func retirementInventoryFixture(t *testing.T) (*Store, CaseRetirementCandidate, time.Time) {
	t.Helper()
	s, _, input, actor, now, _ := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "inventory-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "inventory-close", "cancel", now)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Unix(0, int64(c.Closed+caseMetadataRetention))
	plans, e := s.PlanCaseRetirement(at)
	if e != nil || len(plans) != 1 {
		t.Fatal(plans, e)
	}
	return s, plans[0], at
}

func TestRetirementInventoryIncludesActualControlAndOldGenerations(t *testing.T) {
	s, candidate, at := retirementInventoryFixture(t)
	control := filepath.Join(s.root, candidate.Case.String(), "control")
	old, e := store.EncodeHeader(store.Header{Kind: 9, Owner: candidate.Case, Generation: 7})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(control, "control-000007.wal"), old, 0600); e != nil {
		t.Fatal(e)
	}
	snapshot, e := store.EncodeControlSnapshot(store.Header{Kind: 9, Owner: candidate.Case, Generation: 7, BaseSeq: uint64(candidate.Revision)}, s.state(candidate.Case), 0, s.validator(candidate.Case))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(control, "control-000007.snap"), snapshot, 0600); e != nil {
		t.Fatal(e)
	}
	before := requiredInspectionFiles(t, s.root)
	files, e := s.InspectCaseRetirementFiles(t.Context(), candidate, at)
	if e != nil || len(files) != 4 {
		t.Fatal(files, e)
	}
	checkRetirementInventoryHashes(t, s, files, candidate.Case)
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("inventory changed files")
	}
}

func checkRetirementInventoryHashes(t *testing.T, s *Store, files []CaseRetirementFile, id domain.ID) {
	t.Helper()
	previous := ""
	for _, file := range files {
		if file.Name <= previous {
			t.Fatal("inventory not fixed order")
		}
		raw, e := os.ReadFile(filepath.Join(s.root, id.String(), filepath.FromSlash(file.Name)))
		if e != nil {
			t.Fatal(e)
		}
		if file.SHA != sha256.Sum256(raw) || uint64(file.Bytes) != uint64(len(raw)) {
			t.Fatal("inventory lost byte identity")
		}
		previous = file.Name
	}
}

func TestRetirementInventoryRejectsUnknownForeignAndStaleWithoutChanges(t *testing.T) {
	for _, damage := range []string{"unknown", "foreign", "stale", "cancel"} {
		t.Run(damage, func(t *testing.T) {
			s, candidate, at := retirementInventoryFixture(t)
			ctx := damageRetirementInventory(t, s, &candidate, damage)
			before := requiredInspectionFiles(t, s.root)
			_, e := s.InspectCaseRetirementFiles(ctx, candidate, at)
			if e == nil {
				t.Fatal("unsafe inventory accepted", damage)
			}
			if damage == "cancel" && !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
				t.Fatal("failed inspection changed files")
			}
		})
	}
}

func damageRetirementInventory(t *testing.T, s *Store, candidate *CaseRetirementCandidate, damage string) context.Context {
	t.Helper()
	control := filepath.Join(s.root, candidate.Case.String(), "control")
	switch damage {
	case "unknown":
		if e := os.WriteFile(filepath.Join(control, "unrelated.txt"), []byte("unrelated"), 0600); e != nil {
			t.Fatal(e)
		}
	case "foreign":
		raw, e := store.EncodeHeader(store.Header{Kind: 9, Owner: domain.NewID(), Generation: 7})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(control, "control-000007.wal"), raw, 0600); e != nil {
			t.Fatal(e)
		}
	case "stale":
		candidate.Head[0] ^= 1
	case "cancel":
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		return ctx
	}
	return t.Context()
}
