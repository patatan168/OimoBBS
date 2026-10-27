// 旧上限の保全を維持したまま、異なる期限の実ZIPを個別回収して再起動する。
package disclosure

import (
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestLegacyExportCleanupKeepsHoldAndReopens(t *testing.T) {
	s, key, c, actor, now := capacityActiveCase(t)
	c, first, e := s.Generate(c.ID, actor, c.ETag(), "legacy-zip-one", "提出", []string{}, now)
	if e != nil {
		t.Fatal(e)
	}
	later := time.Now()
	c, second, e := s.Generate(c.ID, actor, c.ETag(), "legacy-zip-two", "提出", []string{}, later)
	if e != nil {
		t.Fatal(e)
	}
	c = fillCaseAuditForTest(t, s, c, actor, later, MaxCaseAudits)
	at := time.Unix(0, int64(first.Until))
	checkLegacyExportEnableRefusals(t, s, at)
	if e = s.EnableExportCleanup(50); e != nil {
		t.Fatal(e)
	}
	checkInvalidSignedExportCleanup(t, s, c, now)
	if e = s.Sweep(at); e != nil {
		t.Fatal(e)
	}
	c = checkLegacyExportResult(t, s, c, first, second, 1, at)
	root := s.root
	if e = InspectVersion(root, key, 49); e == nil {
		t.Fatal("reader49 accepted export cleanup")
	}
	if e = InspectVersion(root, key, 50); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	checkLegacySecondZIPAndClose(t, reopened, c, first, second, actor)
}

func checkLegacyExportEnableRefusals(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	before := requiredInspectionFiles(t, s.root)
	if e := s.Sweep(at); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	if e := s.EnableCaseCompletionTail(49); e != nil {
		t.Fatal(e)
	}
	if e := s.Sweep(at); !errors.Is(e, ErrLimit) {
		t.Fatal("terminal tail erased ZIP", e)
	}
	if e := s.EnableExportCleanup(49); e == nil {
		t.Fatal("reader49 enabled export cleanup")
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("failed preparation changed files")
	}
}

func checkLegacyExportResult(t *testing.T, s *Store, c Case, first, second Export, count uint64, at time.Time) Case {
	t.Helper()
	latest, e := s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if latest.State != "active" || latest.Until != c.Until || uint64(latest.Revision) != MaxCaseAudits+count {
		t.Fatal("hold changed", latest)
	}
	if _, e = os.Stat(s.exportPath(c.ID, first.ID)); !os.IsNotExist(e) {
		t.Fatal("first ZIP survived", e)
	}
	if count == 1 {
		if _, e = os.Stat(s.exportPath(c.ID, second.ID)); e != nil {
			t.Fatal("second ZIP missing", e)
		}
	}
	if rows, e := s.Records(latest, at); e != nil || len(rows) != 1 {
		t.Fatal("held original unavailable", e)
	}
	return latest
}

func checkLegacySecondZIPAndClose(t *testing.T, s *Store, c Case, first, second Export, actor domain.ID) {
	t.Helper()
	if e := s.EnableExportCleanup(50); e != nil {
		t.Fatal(e)
	}
	at := time.Unix(0, int64(second.Until))
	if e := s.Sweep(at); e != nil {
		t.Fatal(e)
	}
	c = checkLegacyExportResult(t, s, c, first, second, 2, at)
	if _, e := os.Stat(s.exportPath(c.ID, second.ID)); !os.IsNotExist(e) {
		t.Fatal("second ZIP survived", e)
	}
	before := requiredInspectionFiles(t, s.root)
	if e := s.Sweep(at); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("repeat sweep appended")
	}
	c, e := s.Release(c.ID, actor, c.ETag(), "legacy-final-cancel", "取消", at)
	if e != nil || c.State != "closed" || uint64(c.Revision) != MaxCaseAudits+4 {
		t.Fatal(c, e)
	}
	if e = InspectVersion(s.root, s.key, 50); e != nil {
		t.Fatal(e)
	}
}

func TestExportCleanupProjectionRejectsUnexpiredAndScopeChanges(t *testing.T) {
	old := Case{ID: domain.NewID(), State: "active", Until: 100, Exports: []Export{{ID: domain.NewID(), State: "ready", Until: 20}}}
	next := old
	next.Exports = append([]Export{}, old.Exports...)
	next.Exports[0].State = "removed"
	if e := validateExportCleanupProjection(old, next, 20); e != nil {
		t.Fatal(e)
	}
	if e := validateExportCleanupProjection(old, next, 19); e == nil {
		t.Fatal("unexpired ZIP removed")
	}
	if e := validateExportCleanupProjection(old, next, old.Until); e == nil {
		t.Fatal("expired case used ZIP-only cleanup")
	}
	next.Until++
	if e := validateExportCleanupProjection(old, next, 20); e == nil {
		t.Fatal("hold changed")
	}
	next = old
	if e := validateExportCleanupProjection(old, next, 20); e == nil {
		t.Fatal("no-op consumed quota")
	}
}

// checkInvalidSignedExportCleanup は正しい鍵で署名した期限前回収を実Control保存前に拒否する。
func checkInvalidSignedExportCleanup(t *testing.T, s *Store, c Case, now time.Time) {
	t.Helper()
	seq, previous, e := s.caseAuditPosition(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c.Revision = domain.U64(seq)
	c.Exports = append([]Export{}, c.Exports...)
	c.Exports[0].State = "removed"
	a := Audit{Owner: c.ID, Seq: c.Revision, At: domain.Time(now.UnixNano()), Actor: c.Creator, Action: exportCleanupAction, Purpose: "signed premature cleanup", Columns: []string{}, Case: c}
	frame, _ := caseAuditRecordForTest(t, s, a, previous)
	raw, e := store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	before := requiredInspectionFiles(t, s.root)
	if result := s.logs[c.ID].Append(raw); result.Status != store.NotWritten {
		t.Fatal("invalid signed cleanup reached writer", result)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("premature cleanup changed files")
	}
}

func TestExportCleanupTailBudgetsRemainSeparate(t *testing.T) {
	var counts caseTailCounts
	for n := uint64(1); n <= maxCaseExports; n++ {
		if e := counts.observe(Audit{Seq: domain.U64(MaxCaseAudits + n), Action: exportCleanupAction}); e != nil {
			t.Fatal(e)
		}
	}
	for n := uint64(1); n <= caseTerminalAudits; n++ {
		if e := counts.observe(Audit{Seq: domain.U64(MaxCaseAudits + maxCaseExports + n), Action: "cleanup"}); e != nil {
			t.Fatal(e)
		}
	}
	if e := counts.observe(Audit{Seq: domain.U64(MaxCaseAudits + maxCaseExports + caseTerminalAudits + 1), Action: "cleanup"}); !errors.Is(e, ErrLimit) {
		t.Fatal("ZIP budget admitted extra terminal row", e)
	}
}
