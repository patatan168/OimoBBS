// 未受理の期限前保全が、元期限後の照会/提出・再起動・解除/満了を通して有効なことを検査する。
package disclosure

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"os"
	"testing"
	"time"
)

func TestRejectedHoldSourceExpiryExportRestartAndRelease(t *testing.T) {
	s, key, c, actor, then, rows := rejectedExportFixtureAt(t, 2*24*time.Hour)
	c, e := s.PrepareRejectedHold(c.ID, actor, c.ETag(), "hold-rejected", "接続保全", rows, then)
	if e != nil || c.State != "preparing" {
		t.Fatal(c, e)
	}
	c, e = s.ResumeRejectedHold(c.ID, actor, c.ETag(), rows, then, func() error { return nil })
	if e != nil || c.Rejected.State != "active" || c.State != "active" {
		t.Fatal(c, e)
	}
	now := time.Now()
	if rows[0].Expires >= domain.Time(now.UnixNano()) {
		t.Fatal("fixture source not expired")
	}
	if e = InspectVersion(s.root, key, 53); e == nil {
		t.Fatal("reader53 accepted hold")
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	copies, e := s.RejectedRecords(c, now)
	if e != nil || len(copies) != 1 || copies[0].Source() != rows[0].Source() {
		t.Fatal(copies, e)
	}
	c, v, e := s.GenerateRejected(c.ID, actor, c.ETag(), "held-export", "提出", []string{"connection"}, copies, now)
	if e != nil || !v.RejectedHeld || v.Until <= rows[0].Expires {
		t.Fatal(v, e)
	}
	raw, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
	if e != nil || m.RecordKind != "not_accepted" {
		t.Fatal(m, e)
	}
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range z.File {
		if f.Name != "readme.txt" {
			continue
		}
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		text, err := io.ReadAll(r)
		r.Close()
		if err != nil || !bytes.Contains(text, []byte("案件の保全期限まで保持")) || bytes.Contains(text, []byte("案件保全コピーは作成しておらず")) {
			t.Fatal("incorrect held-record explanation", err)
		}
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "release-rejected", "解除", now)
	if e != nil || c.State != "closed" || c.Rejected.State != "removed" {
		t.Fatal(c, e)
	}
	if _, e = s.RejectedRecords(c, now); !errors.Is(e, ErrExpired) {
		t.Fatal("released copy visible", e)
	}
	if _, e = os.Stat(s.itemPath(c.ID, rows[0].RecordID)); !os.IsNotExist(e) {
		t.Fatal("released file remains", e)
	}
}

func TestRejectedHoldIntentGCProtectionAndInterruptedCopy(t *testing.T) {
	s, key, c, actor, now, rows := rejectedExportFixture(t)
	c, e := s.PrepareRejectedHold(c.ID, actor, c.ETag(), "hold-rejected", "接続保全", rows, now)
	if e != nil {
		t.Fatal(e)
	}
	inspections, e := InspectRequiredCaseMetadataVersion(s.root, key, 54)
	if e != nil {
		t.Fatal(e)
	}
	at := domain.Time(now.UnixNano())
	protection, e := PrepareRequiredGCProtection(inspections, nil, nil, at, at)
	if e != nil {
		t.Fatal(e)
	}
	if expected := protection.rejectedConnections[requiredGCKey{c.Scope.Board, rows[0].RecordID}]; expected != rows[0].Source().ProposalSHA {
		t.Fatal("pending intent did not protect source")
	}
	ref := rows[0].Source()
	identity := evidence.RequiredPostingIdentity{ProposalID: ref.Record, ProposalSHA: ref.ProposalSHA, DecisionID: domain.NewID(), DecisionSHA: ref.DecisionSHA}
	if held, e := protection.PairHeld(c.Scope.Board, identity, at); e != nil || held {
		t.Fatal("connection hold extended input body retention", held, e)
	}
	if held, e := protection.RejectedConnectionHeld(c.Scope.Board, identity, at); e != nil || !held {
		t.Fatal("pending connection not protected", held, e)
	}
	stop := errors.New("stop after copy")
	s.checkpoint = func(stage string) error {
		if stage == "hold:copy" {
			return stop
		}
		return nil
	}
	if _, e = s.ResumeRejectedHold(c.ID, actor, c.ETag(), rows, now, func() error { return nil }); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e = s.Get(c.ID)
	if e != nil || c.Rejected.Items[0].State != "pending" {
		t.Fatal(c, e)
	}
	c, e = s.PrepareRejectedHold(c.ID, actor, c.ETag(), "retry-rejected", "再開", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ResumeRejectedHold(c.ID, actor, c.ETag(), rows, now, func() error { return nil })
	if e != nil || c.Rejected.State != "active" {
		t.Fatal(c, e)
	}
	if e = s.Sweep(time.Unix(0, int64(c.Until))); e != nil {
		t.Fatal(e)
	}
	c, e = s.Get(c.ID)
	raw, _ := json.Marshal(c)
	if e != nil || c.Rejected.State != "removed" || bytes.Contains(raw, []byte("connection_result")) {
		t.Fatal(c, e)
	}
}

func TestRejectedHoldCopyChangeAndCancellationRefuseCompletion(t *testing.T) {
	s, _, c, actor, now, rows := rejectedExportFixture(t)
	c, e := s.PrepareRejectedHold(c.ID, actor, c.ETag(), "hold-rejected", "保全", rows, now)
	if e != nil {
		t.Fatal(e)
	}
	cancelled := false
	guard := func() error {
		if !cancelled {
			cancelled = true
			_, e := s.Release(c.ID, actor, c.ETag(), "cancel-rejected", "取消", now)
			return e
		}
		return nil
	}
	if _, e := s.ResumeRejectedHold(c.ID, actor, c.ETag(), rows, now, guard); !errors.Is(e, ErrConflict) {
		t.Fatal("cancelled case completed", e)
	}
	c, e = s.Get(c.ID)
	if e != nil || c.State != "closed" {
		t.Fatal(c, e)
	}
}

func TestRejectedHoldChangedCopyPreventsOriginalGC(t *testing.T) {
	s, key, c, actor, now, rows := rejectedExportFixture(t)
	c, e := s.PrepareRejectedHold(c.ID, actor, c.ETag(), "hold-rejected", "保全", rows, now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.ResumeRejectedHold(c.ID, actor, c.ETag(), rows, now, func() error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Extend(c.ID, actor, c.ETag(), "extend-rejected", "延長", c.Until+domain.Time(24*time.Hour), now)
	if e != nil {
		t.Fatal(e)
	}
	inspections, e := InspectRequiredCaseMetadataVersion(s.root, key, 54)
	if e != nil {
		t.Fatal(e)
	}
	if e = InspectRequiredCompletedCopies(s.root, key, inspections, now); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(s.itemPath(c.ID, rows[0].RecordID), []byte(`{"changed":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = InspectRequiredCompletedCopies(s.root, key, inspections, now); e == nil {
		t.Fatal("changed completed copy ignored before GC")
	}
	if _, e = s.RejectedRecords(c, now); e == nil {
		t.Fatal("changed copy disclosed")
	}
}
