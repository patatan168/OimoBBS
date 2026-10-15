// 原本が回収済みでも完成copyを照合し、期限内の欠落・改変と位置/採番の差替えを拒否する。
package disclosure

import (
	"crypto/ed25519"
	"oimobbs/internal/app"
	"oimobbs/internal/evidence"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestRequiredCompletedCopyAfterOriginalGCAndLoss(t *testing.T) {
	s, h, j, key, c, actor, receipt, records, _, day := requiredReservationFixture(t)
	at := records[0].Expires + 1
	check := func() error { _, e := h.Fetch(receipt, map[uint64]*evidence.Journal{day: j}, at); return e }
	c, e := s.ResumeRequiredReserved(c.ID, actor, c.ETag(), records, receipt, time.Unix(0, int64(at)), check)
	if e != nil {
		t.Fatal(e)
	}
	released, e := h.Release(receipt, at)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	identity, e := app.PostingRetirementIdentity(records[0].Proposal, records[0].Decision)
	if e != nil {
		t.Fatal(e)
	}
	if n, e := j.PruneRequired(at, func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) { return &identity, nil }, h.Held, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	rows, e := InspectRequiredCaseMetadataVersion(s.root, key, 46)
	if e != nil {
		t.Fatal(e)
	}
	if e = InspectRequiredCompletedCopies(s.root, key, rows, time.Unix(0, int64(at))); e != nil {
		t.Fatal("copy required live original after GC", e)
	}
	path := s.itemPath(c.ID, c.Items[0].Record)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"missing", "changed"} {
		if kind == "missing" {
			e = os.Remove(path)
		} else {
			e = os.WriteFile(path, []byte("changed"), 0600)
		}
		if e != nil {
			t.Fatal(e)
		}
		before := requiredInspectionFiles(t, s.root)
		if e = InspectRequiredCompletedCopies(s.root, key, rows, time.Unix(0, int64(at))); e == nil {
			t.Fatal("incomplete copy accepted", kind)
		}
		if !reflect.DeepEqual(before, requiredInspectionFiles(t, s.root)) {
			t.Fatal("copy inspection wrote files")
		}
		if e = os.WriteFile(path, raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = InspectRequiredCompletedCopies(s.root, key, rows, time.Unix(0, int64(c.RetentionUntil()))); e != nil {
		t.Fatal("expired copy required restoration", e)
	}
}

func TestRequiredCopyRejectsChangedPostNumberBeforeSave(t *testing.T) {
	s, _, _, key, c, actor, receipt, records, now, _ := requiredReservationFixture(t)
	changed := records[0]
	changed.Post++
	if e := app.ValidateRequiredHeldCopy(c.Scope.Board, receipt.Postings[0], changed, 10, key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("copy post number not tied to actual frame")
	}
	_, e := s.ResumeRequiredReserved(c.ID, actor, c.ETag(), []app.AcceptedEvidence{changed}, receipt, now, func() error { return nil })
	if e == nil {
		t.Fatal("changed post saved")
	}
	if _, e = os.Lstat(s.itemPath(c.ID, c.Items[0].Record)); !os.IsNotExist(e) {
		t.Fatal("changed copy appeared", e)
	}
}
