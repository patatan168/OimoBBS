// 実署名連鎖を上限近くまで保存し、照会拒否後の取消・元解除・期限回収を検証する。
package disclosure

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// fillCaseAuditForTest は同時刻の試験監査を一行frameで署名保存し、署名連鎖を構成する。
// アプリの容量拒否前の既存履歴も作れ、各行の署名/seq/型は実Control列で検査する。
func fillCaseAuditForTest(t *testing.T, s *Store, c Case, actor domain.ID, now time.Time, target uint64) Case {
	t.Helper()
	first, previous, e := s.caseAuditPosition(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	for seq := first; seq <= target; seq++ {
		c.Revision = domain.U64(seq)
		a := Audit{Owner: c.ID, Seq: c.Revision, At: domain.Time(now.UnixNano()), Actor: actor, Action: capacityHistoryAction(c), Purpose: "capacity history", Columns: []string{}, Case: c}
		frame, event := caseAuditRecordForTest(t, s, a, previous)
		previous = event.EventSHA
		raw, e := store.EncodeFrame(frame)
		if e != nil {
			t.Fatal(e)
		}
		if result := s.logs[c.ID].Append(raw); result.Status != store.Durable {
			t.Fatal(result)
		}
	}
	result, e := s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	return result
}

func caseAuditRecordForTest(t *testing.T, s *Store, a Audit, previous domain.Hash) (store.Frame, evidence.Event) {
	t.Helper()
	payload, e := json.Marshal(a)
	if e != nil {
		t.Fatal(e)
	}
	event, e := evidence.Seal(evidence.Source{Owner: a.Owner, Seq: uint64(a.Seq)}, domain.NewID(), "receipt", payload, previous, 10, s.key)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := s.caseAuditFrame(a, event, payload)
	if e != nil {
		t.Fatal(e)
	}
	return frame, event
}

func capacityActiveCase(t *testing.T) (*Store, ed25519.PrivateKey, Case, domain.ID, time.Time) {
	t.Helper()
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "capacity-create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "capacity-hold", "保全", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	return s, key, c, actor, now
}

func TestCaseAuditCapacityStillAllowsReleaseAndReopen(t *testing.T) {
	s, key, c, actor, now := capacityActiveCase(t)
	c = fillCaseAuditForTest(t, s, c, actor, now, maxRegularCaseAudits)
	checkCaseCapacityExportRefusal(t, s, c, actor, now)
	c, e := s.Release(c.ID, actor, c.ETag(), "capacity-release", "取消", now)
	if e != nil || c.State != "closed" || uint64(c.Revision) != maxRegularCaseAudits+2 {
		t.Fatal(c, e)
	}
	if _, e = os.Stat(s.artifactDir(c.ID, "items")); !os.IsNotExist(e) {
		t.Fatal("copies survived release", e)
	}
	root := s.root
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	current, e := reopened.Get(c.ID)
	if e != nil || current.ETag() != c.ETag() {
		t.Fatal(current, e)
	}
}

func checkCaseCapacityExportRefusal(t *testing.T, s *Store, c Case, actor domain.ID, now time.Time) {
	t.Helper()
	before := requiredInspectionFiles(t, s.root)
	if _, v, e := s.Generate(c.ID, actor, c.ETag(), "over-capacity-export", "提出", []string{}, now); !errors.Is(e, ErrLimit) || v.ID != (domain.ID{}) {
		t.Fatal("export consumed finalization capacity", v, e)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("capacity refusal changed files")
	}
}

func TestCaseAuditCapacityRequiredUnreflectedSourceCanClose(t *testing.T) {
	s, h, _, key, c, actor, receipt, _, now, _ := requiredReservationPreparedFixture(t)
	c = fillCaseAuditForTest(t, s, c, actor, now, MaxCaseAudits)
	if e := s.EnableCaseCompletionTail(49); e != nil {
		t.Fatal(e)
	}
	c, e := s.Release(c.ID, actor, c.ETag(), "capacity-cancel", "取消", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ReconcileRequiredReservation(c.ID, actor, c.ETag(), receipt, now)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(receipt, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, now)
	if e != nil || c.Required.Released == nil || uint64(c.Revision) > MaxCaseAudits+caseTerminalAudits {
		t.Fatal(c, e)
	}
	rows, sources := inspectedRequiredFixtureVersion(t, s, key, c, 49)
	if e = CheckRequiredCaseReservations(rows, sources); e != nil {
		t.Fatal("terminal signature history invalid", e)
	}
}

func TestCaseAuditCapacityExportExpiryAndCaseExpiry(t *testing.T) {
	s, _, c, actor, now := capacityActiveCase(t)
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "capacity-export", "提出", []string{}, now)
	if e != nil {
		t.Fatal(e)
	}
	c = fillCaseAuditForTest(t, s, c, actor, now, regularCaseAuditLimit(c))
	checkCaseCapacityExportRefusal(t, s, c, actor, now)
	if e = s.Sweep(time.Unix(0, int64(v.Until))); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.exportPath(c.ID, v.ID)); !os.IsNotExist(e) {
		t.Fatal("expired ZIP survived", e)
	}
	c, e = s.Get(c.ID)
	if e != nil || c.Exports[0].State != "removed" || uint64(c.Revision) != maxRegularCaseAudits {
		t.Fatal(c, e)
	}
	if e = s.Sweep(time.Unix(0, int64(c.Until))); e != nil {
		t.Fatal(e)
	}
	c, e = s.Get(c.ID)
	if e != nil || c.State != "closed" {
		t.Fatal(c, e)
	}
}

func TestCaseAuditCapacityHTTPTerminalReservationAndRelease(t *testing.T) {
	s, owner, c, actor, receipt, _, _, key := reservedHTTPFixtureWithReference(t, false)
	now := time.Now().UTC()
	c = fillCaseAuditForTest(t, s, c, actor, now, MaxCaseAudits)
	if e := s.EnableCaseCompletionTail(49); e != nil {
		t.Fatal(e)
	}
	c, e := s.Release(c.ID, actor, c.ETag(), "capacity-http-cancel", "取消", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ReconcileHTTPReservation(c.ID, actor, c.ETag(), receipt, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = owner.ReleaseOptionalHold(t.Context(), c.ID, c.Revision, now); e != nil {
		t.Fatal(e)
	}
	released, found, e := owner.OptionalHoldReceipt(c.ID)
	if e != nil || !found {
		t.Fatal(released, e)
	}
	c, e = s.RecordHTTPRelease(c.ID, actor, c.ETag(), released, time.Now())
	if e != nil || c.HTTP.Released == nil || uint64(c.Revision) > MaxCaseAudits+caseTerminalAudits {
		t.Fatal(c, e)
	}
	checkCapacityHTTPRelease(t, s, owner, released, key)
}

func checkCapacityHTTPRelease(t *testing.T, s *Store, owner *evidence.OptionalStore, released evidence.OptionalHoldReceipt, key ed25519.PrivateKey) {
	t.Helper()
	if e := owner.CheckOptionalHoldRelease(released); e != nil {
		t.Fatal(e)
	}
	if e := InspectVersion(s.root, key, 49); e != nil {
		t.Fatal("HTTP terminal signatures invalid", e)
	}
}

// 旧版で終端枠まで使い切った履歴は、監査保存できない物理削除を先行させない。
func TestCaseAuditLegacyFullReleasingPreservesCopies(t *testing.T) {
	s, _, c, actor, now := capacityActiveCase(t)
	c = fillCaseAuditForTest(t, s, c, actor, now, MaxCaseAudits-1)
	seq, previous, e := s.caseAuditPosition(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c.State, c.Closed, c.Revision = "releasing", domain.Time(now.UnixNano()), domain.U64(seq)
	a := Audit{Owner: c.ID, Seq: c.Revision, At: c.Closed, Actor: actor, Action: "release", Purpose: "legacy full cancellation", Columns: []string{}, Case: c}
	frame, _ := caseAuditRecordForTest(t, s, a, previous)
	raw, e := store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	if result := s.logs[c.ID].Append(raw); result.Status != store.Durable {
		t.Fatal(result)
	}
	before := requiredInspectionFiles(t, s.root)
	if e = s.Sweep(now); !errors.Is(e, ErrLimit) {
		t.Fatal("legacy full audit bypassed cap", e)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("unsigned physical cleanup advanced")
	}
	checkLegacyCaseCompletionTail(t, s, c, now)

}

// capacityHistoryAction は完成案件の照会、copy待ち案件の同範囲intent再送を表す。
func capacityHistoryAction(c Case) string {
	if c.State == "preparing" || c.State == "partial" {
		if c.HTTP != nil {
			return "http_hold_intent"
		}
		return "hold_intent"
	}
	return "query"
}

func checkLegacyCaseCompletionTail(t *testing.T, s *Store, c Case, now time.Time) {
	t.Helper()
	before := requiredInspectionFiles(t, s.root)
	if e := s.EnableCaseCompletionTail(48); e == nil {
		t.Fatal("reader48 enabled tail")
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("failed enable wrote files")
	}
	if e := s.EnableCaseCompletionTail(49); e != nil {
		t.Fatal(e)
	}
	if e := s.Sweep(now.Add(-time.Nanosecond)); !errors.Is(e, ErrExpired) {
		t.Fatal("tail swept before clock floor", e)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("clock rollback changed copies")
	}
	if e := s.Sweep(now); e != nil {
		t.Fatal(e)
	}
	checkLegacyCompletedHistory(t, s, c)
	checkCaseTailBoundaries(t, s, c, now)
}

func checkLegacyCompletedHistory(t *testing.T, s *Store, c Case) {
	t.Helper()
	latest, e := s.Get(c.ID)
	if e != nil || latest.State != "closed" || uint64(latest.Revision) != MaxCaseAudits+1 {
		t.Fatal(latest, e)
	}
	if _, e = os.Stat(s.artifactDir(c.ID, "items")); !os.IsNotExist(e) {
		t.Fatal("tail left copies", e)
	}
	if e = InspectVersion(s.root, s.key, 48); e == nil {
		t.Fatal("reader48 accepted completion tail")
	}
	if e = InspectVersion(s.root, s.key, 49); e != nil {
		t.Fatal(e)
	}
	if _, e = s.append(latest, latest.Creator, "query", "query after tail", nil, "", "", nil, time.Now()); !errors.Is(e, ErrLimit) {
		t.Fatal("tail admitted query", e)
	}
}

// checkCaseTailBoundaries は有効署名でも通常操作/六行超過を実Control保存前に拒否する。
func checkCaseTailBoundaries(t *testing.T, s *Store, c Case, now time.Time) {
	t.Helper()
	latest, e := s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	checkInvalidSignedTail(t, s, latest, "query", now)
	for uint64(latest.Revision) < MaxCaseAudits+caseTerminalAudits {
		latest, e = s.append(latest, latest.Creator, "cleanup", "tail boundary fixture", nil, "", "", nil, now)
		if e != nil {
			t.Fatal(e)
		}
	}
	before := requiredInspectionFiles(t, s.root)
	if _, e = s.append(latest, latest.Creator, "cleanup", "overflow", nil, "", "", nil, now); !errors.Is(e, ErrLimit) {
		t.Fatal(e)
	}
	checkInvalidSignedTail(t, s, latest, "cleanup", now)
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("overflow changed history")
	}
}

func checkInvalidSignedTail(t *testing.T, s *Store, c Case, action string, now time.Time) {
	t.Helper()
	seq, previous, e := s.caseAuditPosition(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c.Revision = domain.U64(seq)
	a := Audit{Owner: c.ID, Seq: c.Revision, At: domain.Time(now.UnixNano()), Actor: c.Creator, Action: action, Purpose: "signed invalid tail", Columns: []string{}, Case: c}
	frame, _ := caseAuditRecordForTest(t, s, a, previous)
	raw, e := store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	before := requiredInspectionFiles(t, s.root)
	if result := s.logs[c.ID].Append(raw); result.Status != store.NotWritten {
		t.Fatal("invalid signed tail reached writer", result)
	}
	if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
		t.Fatal("invalid tail mutated")
	}
}
