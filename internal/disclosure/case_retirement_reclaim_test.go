// 実制御全世代の物理回収・各中断点からの固定再開・元/未知fileの非変更拒否を検査する。
package disclosure

import (
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func retirementReclaimFixture(t *testing.T) (*Store, ed25519.PrivateKey, CaseRetirementCandidate, evidence.Event, time.Time) {
	t.Helper()
	s, candidate, at := retirementInventoryFixture(t)
	control := filepath.Join(s.root, candidate.Case.String(), "control")
	header, e := store.EncodeHeader(store.Header{Kind: 9, Owner: candidate.Case, Generation: 7})
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(control, "control-000007.wal"), header, 0600); e != nil {
		t.Fatal(e)
	}
	snapshot, e := store.EncodeControlSnapshot(store.Header{Kind: 9, Owner: candidate.Case, Generation: 7, BaseSeq: uint64(candidate.Revision)}, s.state(candidate.Case), 0, s.validator(candidate.Case))
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(control, "control-000007.snap"), snapshot, 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"items", "exports", "http"} {
		if e = os.Mkdir(filepath.Join(s.root, candidate.Case.String(), name), 0700); e != nil {
			t.Fatal(e)
		}
	}
	_, event, e := s.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, at)
	if e != nil {
		t.Fatal(e)
	}
	return s, append(ed25519.PrivateKey{}, s.key...), candidate, event, at
}

func TestCaseRetirementReclaimPhysicallyRemovesAllGenerationsAndCopyDirectories(t *testing.T) {
	s, _, candidate, event, at := retirementReclaimFixture(t)
	if e := s.ReclaimCaseRetirement(t.Context(), candidate.Case, event, 51, nil, nil, at); e != nil {
		t.Fatal(e)
	}
	checkRetiredCaseDirectoryAbsent(t, s.root, candidate.Case)
	if cases, e := s.Cases(); e != nil || len(cases) != 0 {
		t.Fatal("case slot not reclaimed", cases, e)
	}
	if e := s.ReclaimCaseRetirement(t.Context(), candidate.Case, event, 51, nil, nil, at); e != nil {
		t.Fatal("finished retirement not idempotent", e)
	}
}

func TestCaseRetirementReclaimRechecksRemainingFileAfterDeletion(t *testing.T) {
	s, _, candidate, event, at := retirementReclaimFixture(t)
	name := filepath.Join(s.root, candidate.Case.String(), "control", "control-000007.wal")
	s.checkpoint = func(point string) error {
		if point != "retirement:file" {
			return nil
		}
		s.checkpoint = nil
		return os.WriteFile(name, []byte("changed after first removal"), 0600)
	}
	if e := s.ReclaimCaseRetirement(t.Context(), candidate.Case, event, 51, nil, nil, at); e == nil {
		t.Fatal("changed remainder was removed")
	}
	if !s.stopped {
		t.Fatal("partial removal did not stop owner")
	}
	if body, e := os.ReadFile(name); e != nil || string(body) != "changed after first removal" {
		t.Fatal("changed file was not preserved", e)
	}
}

func checkRetiredCaseDirectoryAbsent(t *testing.T, root string, id domain.ID) {
	t.Helper()
	if _, e := os.Lstat(filepath.Join(root, id.String())); !os.IsNotExist(e) {
		t.Fatal("private case directory remained", e)
	}
}

func TestCaseRetirementReclaimResumesEachRemovalBoundary(t *testing.T) {
	for _, point := range []string{"retirement:file", "retirement:directories", "retirement:complete"} {
		t.Run(point, func(t *testing.T) {
			s, key, candidate, event, at := retirementReclaimFixture(t)
			s.checkpoint = func(name string) error {
				if name == point {
					return context.Canceled
				}
				return nil
			}
			if e := s.ReclaimCaseRetirement(t.Context(), candidate.Case, event, 51, nil, nil, at); !errors.Is(e, context.Canceled) {
				t.Fatal("removal checkpoint not reached", e)
			}
			if !s.stopped {
				t.Fatal("uncertain removal did not stop owner")
			}
			if e := ResumeCaseRetirement(t.Context(), s.root, key, candidate.Case, event, 51, nil, nil, at.Add(time.Second)); e != nil {
				t.Fatal("signed remainder could not resume", e)
			}
			checkRetiredCaseDirectoryAbsent(t, s.root, candidate.Case)
		})
	}
}

func TestCaseRetirementReclaimRefusesChangedRemainderBeforeDeletion(t *testing.T) {
	for _, damage := range []string{"unknown", "foreign", "bytes", "copy", "symlink", "hardlink", "reader", "clock", "context", "signature"} {
		t.Run(damage, func(t *testing.T) {
			s, _, candidate, event, at := retirementReclaimFixture(t)
			ctx := damageRetirementReclaim(t, s, candidate, damage)
			reader := uint32(51)
			if damage == "reader" {
				reader = 50
			}
			if damage == "clock" {
				at = at.Add(-time.Nanosecond)
			}
			if damage == "signature" {
				event.EventSHA[0] ^= 1
			}
			before := requiredInspectionFiles(t, s.root)
			if e := s.ReclaimCaseRetirement(ctx, candidate.Case, event, reader, nil, nil, at); e == nil {
				t.Fatal("unsafe removal accepted", damage)
			}
			if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
				t.Fatal("invalid remainder changed files")
			}
		})
	}
}

func damageRetirementReclaim(t *testing.T, s *Store, candidate CaseRetirementCandidate, damage string) context.Context {
	t.Helper()
	control := filepath.Join(s.root, candidate.Case.String(), "control")
	path := filepath.Join(control, "control-000007.wal")
	switch damage {
	case "unknown":
		writeRetirementDamage(t, filepath.Join(control, "unknown"), []byte("unknown"))
	case "foreign":
		header, e := store.EncodeHeader(store.Header{Kind: 9, Owner: domain.NewID(), Generation: 7})
		if e != nil {
			t.Fatal(e)
		}
		writeRetirementDamage(t, path, header)
	case "bytes":
		writeRetirementDamage(t, path, []byte("changed"))
	case "copy":
		writeRetirementDamage(t, filepath.Join(s.root, candidate.Case.String(), "items", "copy.json"), []byte("private"))
	case "symlink", "hardlink":
		linkRetirementDamage(t, path, damage)
	case "context":
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		return ctx
	}
	return t.Context()
}

func writeRetirementDamage(t *testing.T, path string, raw []byte) {
	t.Helper()
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
}

func linkRetirementDamage(t *testing.T, path, kind string) {
	t.Helper()
	if kind == "hardlink" {
		if e := os.Link(path, filepath.Join(t.TempDir(), "alias")); e != nil {
			t.Fatal(e)
		}
		return
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("control-000001.wal", path); e != nil {
		t.Fatal(e)
	}
}
