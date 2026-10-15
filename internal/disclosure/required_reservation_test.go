// 実投稿原本/元予約/案件署名/GCを通し、予約参照保存と原期限後copy・解除を検証する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func requiredPostingFrame(t *testing.T, committed domain.Time) (domain.ID, []byte) {
	t.Helper()
	raw, e := os.ReadFile("../../docs/design/fixtures/wal-v1-create.json")
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Board     domain.ID       `json:"board_id_hex"`
		ID        domain.ID       `json:"operation_id_hex"`
		Operation json.RawMessage `json:"operation"`
		DAT       string          `json:"dat_hex"`
	}
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Operation)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	op.Committed, op.After.LastUserAt, op.Dedup.Expires = committed, committed, committed+86400e9
	create.Created, create.Posts[0].Created = committed, committed
	create.Expires = domain.Time(domain.SixMonths(time.Unix(0, int64(committed))).UnixNano())
	op.Payload, _ = json.Marshal(create)
	f.Operation, _ = json.Marshal(op)
	dat, e := hex.DecodeString(f.DAT)
	if e != nil {
		t.Fatal(e)
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: 1, Records: []store.Record{{ID: f.ID, JSON: f.Operation, DAT: dat}}})
	if e != nil {
		t.Fatal(e)
	}
	return f.Board, frame
}

func requiredReservationPreparedFixture(t *testing.T) (*Store, *app.RequiredOriginalHolds, *evidence.Journal, ed25519.PrivateKey, Case, domain.ID, app.RequiredHoldReceipt, []app.AcceptedEvidence, time.Time, uint64) {
	t.Helper()
	now := time.Now().UTC()
	at := domain.Time(now.AddDate(0, -5, 0).UnixNano())
	board, frame := requiredPostingFrame(t, at)
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	threads := filepath.Join(root, "threads")
	if e = os.Mkdir(threads, 0700); e != nil {
		t.Fatal(e)
	}
	day, _ := strconv.ParseUint(time.Unix(0, int64(at)).UTC().Format("20060102"), 10, 64)
	j, e := evidence.OpenJournal(filepath.Join(root, "originals"), board, day, 10, key, app.PostingValidator(strictjson.Validate))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close() })
	p, e := app.OpenPosting(threads, board, 1700000000, []*evidence.Journal{j}, j, at)
	if e != nil {
		t.Fatal(e)
	}
	if result := p.Post(t.Context(), frame, []byte(`{"fixture":true}`), at); result.Status != store.Durable {
		t.Fatal(result)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	rows, e := app.AcceptedRecords([]*evidence.Journal{j})
	if e != nil {
		t.Fatal(e)
	}
	cases := filepath.Join(root, "cases")
	if e = os.Mkdir(cases, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := Open(cases, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = s.Close() })
	actor := domain.NewID()
	c, e := s.Create(Case{Number: "required-source", Reason: "保全", Until: domain.Time(now.Add(60 * 24 * time.Hour).UnixNano()), Scope: Scope{Board: board, From: at - 1, To: at + 1}}, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.PrepareHold(c.ID, actor, c.ETag(), "hold", "原本保全", rows, now)
	if e != nil {
		t.Fatal(e)
	}
	binding, e := s.RequiredReservationBinding(c, now)
	if e != nil {
		t.Fatal(e)
	}
	h, e := app.OpenRequiredOriginalHolds(filepath.Join(root, "source-holds"), board, 10, key, false)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = h.Close() })
	if e = h.Initialize(domain.Time(now.UnixNano())); e != nil {
		t.Fatal(e)
	}
	r, e := h.Reserve(binding, rows, map[uint64]*evidence.Journal{day: j}, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	return s, h, j, key, c, actor, r, rows, now, day
}

func requiredReservationFixture(t *testing.T) (*Store, *app.RequiredOriginalHolds, *evidence.Journal, ed25519.PrivateKey, Case, domain.ID, app.RequiredHoldReceipt, []app.AcceptedEvidence, time.Time, uint64) {
	t.Helper()
	s, h, j, key, c, actor, r, rows, now, day := requiredReservationPreparedFixture(t)
	c, e := s.BindRequiredReservation(c.ID, actor, c.ETag(), r, now)
	if e != nil {
		t.Fatal(e)
	}
	return s, h, j, key, c, actor, r, rows, now, day
}

func TestRequiredReservedCopyAfterExpiryAndRelease(t *testing.T) {
	s, h, j, key, c, actor, receipt, rows, now, day := requiredReservationFixture(t)
	otherBinding := receipt.Binding
	otherBinding.Case = domain.NewID()
	other, e := h.Reserve(otherBinding, rows, map[uint64]*evidence.Journal{day: j}, domain.Time(now.UnixNano()))
	if e != nil {
		t.Fatal(e)
	}
	if e := InspectVersion(s.root, key, 45); e == nil {
		t.Fatal("reader45 accepted required reservation")
	}
	if e := InspectVersion(s.root, key, 46); e != nil {
		t.Fatal(e)
	}
	if e := s.Close(); e != nil {
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
	journals := map[uint64]*evidence.Journal{day: j}
	at := rows[0].Expires + 1
	identity, e := app.PostingRetirementIdentity(rows[0].Proposal, rows[0].Decision)
	if e != nil {
		t.Fatal(e)
	}
	selectOriginal := func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) { return &identity, nil }
	if n, e := j.PruneRequired(at, selectOriginal, h.Held, nil); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	fetched, e := h.Fetch(receipt, journals, at)
	if e != nil {
		t.Fatal(e)
	}
	check := func() error { _, e := h.Fetch(receipt, journals, at); return e }
	c, e = s.ResumeRequiredReserved(c.ID, actor, c.ETag(), fetched, receipt, time.Unix(0, int64(at)), check)
	if e != nil || c.State != "active" {
		t.Fatal(c, e)
	}
	released, e := h.Release(receipt, at)
	if e != nil {
		t.Fatal(e)
	}
	if released.Sequence <= receipt.Sequence+1 {
		t.Fatal("interleaved source history not exercised")
	}
	c, e = s.RecordRequiredRelease(c.ID, actor, c.ETag(), released, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = h.Release(other, at); e != nil {
		t.Fatal(e)
	}
	if n, e := j.PruneRequired(at, selectOriginal, h.Held, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	held, e := s.Records(c, time.Unix(0, int64(at)))
	if e != nil || len(held) != 1 || !bytes.Equal(held[0].Proposal.Payload, rows[0].Proposal.Payload) {
		t.Fatal(held, e)
	}
	if e = InspectVersion(s.root, key, 46); e != nil {
		t.Fatal("released reference replay", e)
	}
}

func TestRequiredReservationRejectsUnboundAndExpiredCopies(t *testing.T) {
	s, h, j, _, c, actor, receipt, rows, now, day := requiredReservationFixture(t)
	bad := receipt
	bad.SHA[0] ^= 1
	if _, e := s.ResumeRequiredReserved(c.ID, actor, c.ETag(), rows, bad, now, func() error { return nil }); e == nil {
		t.Fatal("different reference copied")
	}
	if _, e := s.ResumeRequiredReserved(c.ID, actor, c.ETag(), rows, receipt, now, nil); e == nil {
		t.Fatal("nil source check copied")
	}
	if _, e := s.RecordRequiredRelease(c.ID, actor, c.ETag(), receipt, now); e == nil {
		t.Fatal("pending source released")
	}
	if _, e := s.resumeHold(c, actor, rows, now); e == nil {
		t.Fatal("legacy path bypassed source reservation")
	}
	if _, e := s.Extend(c.ID, actor, c.ETag(), "extend", "延長", c.Until+1, now); e == nil {
		t.Fatal("unreflected source extension")
	}
	calls := 0
	check := func() error {
		calls++
		if calls == 3 {
			return io.ErrUnexpectedEOF
		}
		_, e := h.Fetch(receipt, map[uint64]*evidence.Journal{day: j}, domain.Time(now.UnixNano()))
		return e
	}
	_, e := s.ResumeRequiredReserved(c.ID, actor, c.ETag(), rows, receipt, now, check)
	if !errors.Is(e, io.ErrUnexpectedEOF) {
		t.Fatal(e)
	}
	if _, e = os.Lstat(s.itemPath(c.ID, rows[0].RecordID)); !os.IsNotExist(e) {
		t.Fatal("source check failure wrote copy", e)
	}
	_, e = s.ResumeRequiredReserved(c.ID, actor, c.ETag(), rows, receipt, time.Unix(0, int64(c.Until)), func() error { return nil })
	if e == nil {
		t.Fatal("expired reservation copied")
	}
}

func TestRequiredReservationReferenceIsImmutable(t *testing.T) {
	s, _, _, _, c, actor, receipt, _, now, _ := requiredReservationFixture(t)
	for _, mutate := range []func(*Case){
		func(c *Case) { c.Required = nil },
		func(c *Case) { h := *c.Required; r := h.Reservation; r.SHA[0] ^= 1; h.Reservation = r; c.Required = &h },
		func(c *Case) {
			h := *c.Required
			r := h.Reservation
			r.Binding.Revision++
			h.Reservation = r
			c.Required = &h
		},
	} {
		candidate := c
		mutate(&candidate)
		if _, e := s.append(candidate, actor, "hold_intent", "bad reference", nil, "", "", nil, nil, now); e == nil {
			t.Fatal("saved reference changed")
		}
	}
	current, e := s.Get(c.ID)
	if e != nil || !sameRequiredReceipt(current.Required.Reservation, receipt) || current.Revision != c.Revision {
		t.Fatal(current, e)
	}
}

func TestRequiredSourceFieldCompleteFormat(t *testing.T) {
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{record}, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(raw, []byte(`"required_original_hold":null`)) {
		t.Fatal("missing explicit empty hold")
	}
	var decoded Case
	if e = strictjson.Decode(raw, &decoded); e != nil {
		t.Fatal(e)
	}
	encoded, e := json.Marshal(decoded)
	if e != nil || !bytes.Equal(raw, encoded) {
		t.Fatal("legacy case bytes changed", e)
	}
	var old map[string]json.RawMessage
	_ = json.Unmarshal(raw, &old)
	delete(old, "required_original_hold")
	legacy, _ := json.Marshal(old)
	if err := strictjson.Decode(legacy, &decoded); err == nil {
		t.Fatal("old case format accepted")
	}
	if e = InspectVersion(s.root, key, 45); e != nil {
		t.Fatal(e)
	}
}
