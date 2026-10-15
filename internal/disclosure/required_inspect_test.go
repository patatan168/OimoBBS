// 実署名案件/元台帳の初回未反映・完成・解除を非変更で横断照合し、孤立/巻戻りを拒否する。
package disclosure

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"io/fs"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

type requiredInspectionFile struct {
	Mode fs.FileMode
	Hash domain.Hash
}

func requiredInspectionFiles(t *testing.T, root string) map[string]requiredInspectionFile {
	t.Helper()
	result := map[string]requiredInspectionFile{}
	e := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		value := requiredInspectionFile{Mode: info.Mode()}
		if !entry.IsDir() {
			raw, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			value.Hash = sha256.Sum256(raw)
		}
		result[rel] = value
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func inspectedRequiredFixture(t *testing.T, s *Store, key ed25519.PrivateKey, c Case) ([]RequiredCaseInspection, []app.RequiredHoldReceipt) {
	t.Helper()
	return inspectedRequiredFixtureVersion(t, s, key, c, 46)
}

// inspectedRequiredFixtureVersion は案件/元を指定readerで非変更検査する。
func inspectedRequiredFixtureVersion(t *testing.T, s *Store, key ed25519.PrivateKey, c Case, reader uint32) ([]RequiredCaseInspection, []app.RequiredHoldReceipt) {
	t.Helper()
	root := filepath.Dir(s.root)
	before := requiredInspectionFiles(t, root)
	cases, e := InspectRequiredCaseMetadataVersion(s.root, key, reader)
	if e != nil || len(cases) != 1 {
		t.Fatal(cases, e)
	}
	source, e := app.InspectRequiredOriginalHolds(filepath.Join(root, "source-holds"), c.Scope.Board, 10, key)
	if e != nil || len(source.Receipts) != 1 {
		t.Fatal(source, e)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, root)) {
		t.Fatal("inspection changed files or modes")
	}
	return cases, source.Receipts
}

func TestRequiredCaseInspectionAcrossSourceAndCaseBoundaries(t *testing.T) {
	s, h, j, key, c, actor, receipt, records, now, day := requiredReservationPreparedFixture(t)
	firstRevision := c.Revision
	rows, sources := inspectedRequiredFixture(t, s, key, c)
	if rows[0].Intent == nil || rows[0].Intent.Binding.Revision != firstRevision || rows[0].Intent.At != domain.Time(now.UnixNano()) {
		t.Fatal("first intent missing")
	}
	if e := CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal("source Sync before case reference", e)
	}
	// 新しい保全要求が追記されても元bindingは最初のintent版を指す。
	c, e := s.PrepareHold(c.ID, actor, c.ETag(), "retry", "原本保全", records, now)
	if e != nil || c.Revision == firstRevision {
		t.Fatal(c, e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if rows[0].Intent.Binding.Revision != firstRevision || rows[0].Current.Revision != c.Revision {
		t.Fatal("initial and current revision mixed")
	}
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal(e)
	}
	c, e = s.BindRequiredReservation(c.ID, actor, c.ETag(), receipt, now)
	if e != nil {
		t.Fatal(e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal(e)
	}
	before := requiredInspectionFiles(t, filepath.Dir(s.root))
	if _, e = InspectRequiredCaseMetadataVersion(s.root, key, 45); e == nil {
		t.Fatal("reader45 accepted required reference")
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, filepath.Dir(s.root))) {
		t.Fatal("reader rejection changed files")
	}

	at := records[0].Expires + 1
	fetched, e := h.Fetch(receipt, map[uint64]*evidence.Journal{day: j}, at)
	if e != nil {
		t.Fatal(e)
	}
	check := func() error { _, e := h.Fetch(receipt, map[uint64]*evidence.Journal{day: j}, at); return e }
	c, e = s.ResumeRequiredReserved(c.ID, actor, c.ETag(), fetched, receipt, time.Unix(0, int64(at)), check)
	if e != nil || c.State != "active" {
		t.Fatal(c, e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal("completed case before source release", e)
	}
	oldSource := sources[0]
	released, e := h.Release(receipt, at)
	if e != nil {
		t.Fatal(e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal("source release before case reference", e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal(e)
	}
	if e = CheckRequiredCaseReservations(rows, []app.RequiredHoldReceipt{oldSource}); e == nil {
		t.Fatal("source rollback accepted after signed release")
	}
	// 検査結果は過去intent/最新状態とも独立所有で、変更しても次の検査へ伝播しない。
	rows[0].Intent.Items[0].Source = domain.Hash{}
	rows[0].Current.Items[0].Source = domain.Hash{}
	again, current := inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(again, current); e != nil {
		t.Fatal("inspection alias", e)
	}
}

func TestRequiredCaseInspectionCancellationBeforeBinding(t *testing.T) {
	s, h, _, key, c, actor, receipt, _, now, _ := requiredReservationPreparedFixture(t)
	c, e := s.Release(c.ID, actor, c.ETag(), "cancel", "取消", now)
	if e != nil {
		t.Fatal(e)
	}
	rows, sources := inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal("cancelled case before source release", e)
	}
	if _, e = h.Release(receipt, domain.Time(now.UnixNano())); e != nil {
		t.Fatal(e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal("cancelled unbound release", e)
	}
}

func TestRequiredCaseInspectionRefusesPrematureReleaseAndMissingOrDuplicateSource(t *testing.T) {
	s, h, _, key, c, _, receipt, _, now, _ := requiredReservationFixture(t)
	rows, sources := inspectedRequiredFixture(t, s, key, c)
	if e := CheckRequiredCaseReservations(rows, nil); e == nil {
		t.Fatal("case source missing accepted")
	}
	if e := CheckRequiredCaseReservations(nil, sources); e == nil {
		t.Fatal("orphan source accepted")
	}
	if e := CheckRequiredCaseReservations(append(slices.Clone(rows), rows[0]), sources); e == nil {
		t.Fatal("duplicate case accepted")
	}
	if e := CheckRequiredCaseReservations(rows, append(slices.Clone(sources), sources[0])); e == nil {
		t.Fatal("duplicate source accepted")
	}
	if _, e := h.Release(receipt, domain.Time(now.UnixNano())); e != nil {
		t.Fatal(e)
	}
	rows, sources = inspectedRequiredFixture(t, s, key, c)
	if e := CheckRequiredCaseReservations(rows, sources); e == nil {
		t.Fatal("pending copy source released accepted")
	}
}

func TestRequiredCaseInspectionRefusesBindingAndWholeTargetChanges(t *testing.T) {
	s, _, _, key, c, _, _, _, _, _ := requiredReservationPreparedFixture(t)
	rows, sources := inspectedRequiredFixture(t, s, key, c)
	for _, name := range []string{"intent_revision", "intent_scope", "current_scope", "selection", "intent_source", "current_source", "case_state", "source_expiry", "source_owner", "source_record"} {
		t.Run(name, func(t *testing.T) {
			row := rows[0]
			intent := *row.Intent
			intent.Items = slices.Clone(intent.Items)
			row.Intent = &intent
			row.Current.Items = slices.Clone(row.Current.Items)
			r := sources[0]
			r.Postings = slices.Clone(r.Postings)
			switch name {
			case "intent_revision":
				row.Intent.Binding.Revision++
			case "intent_scope":
				row.Intent.Binding.To++
			case "current_scope":
				row.Current.Scope.To++
			case "selection":
				row.Current.Scope.Records = []domain.ID{domain.NewID()}
			case "intent_source":
				row.Intent.Items[0].Source = domain.Hash{}
			case "current_source":
				row.Current.Items[0].Source = domain.Hash{}
			case "case_state":
				row.Current.State = "active"
			case "source_expiry":
				r.Binding.Until++
			case "source_owner":
				r.Binding.Board = domain.NewID()
			case "source_record":
				r.Postings[0].Identity.ProposalID = domain.NewID()
			}
			if e := CheckRequiredCaseReservation(row, r); e == nil {
				t.Fatal("changed fixed intent or target accepted")
			}
		})
	}
}

func TestRequiredCaseInspectionLeavesCreationAndUnknownFiles(t *testing.T) {
	s, _, _, key, c, _, _, _, _, _ := requiredReservationPreparedFixture(t)
	for _, name := range []string{".create-pending", "unknown"} {
		path := filepath.Join(s.root, name)
		if e := os.WriteFile(path, []byte("pending"), 0600); e != nil {
			t.Fatal(e)
		}
		before := requiredInspectionFiles(t, filepath.Dir(s.root))
		_, e := InspectRequiredCaseMetadataVersion(s.root, key, 46)
		if e == nil || name == ".create-pending" && !errors.Is(e, store.ErrIncomplete) {
			t.Fatal("unknown/pending repaired", e)
		}
		if !reflect.DeepEqual(before, requiredInspectionFiles(t, filepath.Dir(s.root))) {
			t.Fatal("unknown/pending inspection changed files")
		}
		if e = os.Remove(path); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := InspectRequiredCaseMetadataVersion(s.root, key, 46); e != nil {
		t.Fatal(c.ID, e)
	}
}
