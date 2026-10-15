// 案件保全・選択列・署名ZIP・再送・期限・解除・破損拒否を実fileで検証する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*Store, ed25519.PrivateKey, Case, domain.ID, time.Time, app.AcceptedEvidence) {
	t.Helper()
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	root := t.TempDir()
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	s, e := Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now().UTC()
	actor, board := domain.NewID(), domain.NewID()
	at := domain.Time(now.Add(-time.Second).UnixNano())
	until := domain.Time(now.Add(100 * 24 * time.Hour).UnixNano())
	id, op := domain.NewID(), domain.NewID()
	frame := caseFixtureFrame(t, op, at)
	frameHash := domain.Hash(sha256.Sum256(frame))
	p := map[string]any{"source_owner_id": board, "source_subkey": domain.U64(20261004), "source_control_seq": domain.U64(1), "thread_key": domain.U64(123), "operation_id": op, "thread_seq": domain.U64(1), "thread_frame_sha256": frameHash, "committed_at_ns": at, "retention_until_ns": until, "prepared_frame_base64": base64.StdEncoding.EncodeToString(frame), "capture": map[string]any{"schema": "fixture", "input": map[string]string{"name": "sample", "mail": "sage", "title": "title", "body": "PRIVATE_BODY", "credential": "SECRET_CREDENTIAL"}}}
	raw, _ := json.Marshal(p)
	pe, e := evidence.Seal(evidence.Source{Owner: board, Subkey: 20261004, Seq: 1}, id, "evidence_proposal", raw, domain.Hash{}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	d := map[string]any{"source_owner_id": board, "source_subkey": domain.U64(20261004), "source_control_seq": domain.U64(2), "thread_key": domain.U64(123), "operation_id": op, "thread_seq": domain.U64(1), "thread_frame_sha256": frameHash, "proposal_id": id, "proposal_event_sha256": pe.EventSHA, "committed_at_ns": at, "retention_until_ns": until, "decision": "accepted", "recovered": false, "decision_at_ns": at}
	dr, _ := json.Marshal(d)
	de, e := evidence.Seal(evidence.Source{Owner: board, Subkey: 20261004, Seq: 2}, domain.NewID(), "evidence_decision", dr, pe.EventSHA, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	r := app.AcceptedEvidence{RecordID: id, Board: board, Thread: 123, Operation: op, Post: 1, Committed: at, Expires: until, Proposal: evidence.Entry{Event: pe, Payload: raw}, Decision: evidence.Entry{Event: de, Payload: dr}}
	c := Case{Number: "case-1", Reason: "investigation", Scope: Scope{Board: board, From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}}
	return s, key, c, actor, now, r
}
func TestCaseLifecycleAndSelectedExport(t *testing.T) {
	s, key, input, actor, now, record := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create-key", now)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.Create(input, actor, `"evidence:new"`, "create-key", now.Add(time.Second))
	if e != nil || again.ID != c.ID {
		t.Fatal("creation replay", e)
	}
	altered := input
	altered.Reason = "different"
	if _, e = s.Create(altered, actor, `"evidence:new"`, "create-key", now); e != ErrConflict {
		t.Fatal("different replay", e)
	}
	before := c.ETag()
	c, e = s.Hold(c.ID, actor, before, "hold-key", "requested preservation", []app.AcceptedEvidence{record}, now)
	if e != nil || c.State != "active" {
		t.Fatal(c, e)
	}
	c, e = s.Hold(c.ID, actor, before, "hold-key", "requested preservation", []app.AcceptedEvidence{record}, now)
	if e != nil || c.Revision != 3 {
		t.Fatal("hold replay", c, e)
	}
	c, rows, e := s.Query(c.ID, actor, c.ETag(), "query-key", "review", nil, now)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	raw, _ := json.Marshal(rows)
	if bytes.Contains(raw, []byte("PRIVATE_BODY")) || bytes.Contains(raw, []byte("SECRET_CREDENTIAL")) {
		t.Fatal("unselected content leaked")
	}
	c, rows, e = s.Query(c.ID, actor, c.ETag(), "query-content", "review", []string{"content"}, now)
	raw, _ = json.Marshal(rows)
	if e != nil || !bytes.Contains(raw, []byte("PRIVATE_BODY")) || bytes.Contains(raw, []byte("SECRET_CREDENTIAL")) {
		t.Fatal("selection", string(raw), e)
	}
	before = c.ETag()
	c, v, e := s.Generate(c.ID, actor, before, "export-key", "submit", nil, now)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
	_, repeat, e := s.Generate(c.ID, actor, before, "export-key", "submit", nil, now)
	if e != nil || repeat.ID != v.ID {
		t.Fatal("export replay", e)
	}
	data, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := VerifyZIP(bytes.NewReader(data), int64(len(data)), key.Public().(ed25519.PublicKey))
	if e != nil || m.Count != 1 {
		t.Fatal(m, e)
	}
	_, wrong, _ := ed25519.GenerateKey(rand.Reader)
	if _, e = VerifyZIP(bytes.NewReader(data), int64(len(data)), wrong.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("wrong trust key accepted")
	}
	c, f, _, e := s.Download(c.ID, v.ID, actor, c.ETag(), "download-key", "manual submission", now)
	if e != nil {
		t.Fatal(e)
	}
	received, e := io.ReadAll(f)
	f.Close()
	if e != nil || !bytes.Equal(received, data) {
		t.Fatal("download", e)
	}
	if _, f, _, e = s.Download(c.ID, v.ID, actor, c.ETag(), "download-key-2", "second download", now); e == nil {
		f.Close()
		t.Fatal("one-time permission reused")
	}
	c, e = s.RecordTransfer(c.ID, actor, c.ETag(), "transfer-key", "manual handoff", Transfer{Export: v.ID, Organization: "agency", Reference: "req1", Method: "secure media", At: domain.Time(now.UnixNano())}, now)
	if e != nil {
		t.Fatal(e)
	}
	h, e := s.history(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	for _, a := range h {
		raw, _ = json.Marshal(a)
		if bytes.Contains(raw, []byte("PRIVATE_BODY")) || bytes.Contains(raw, []byte("SECRET_CREDENTIAL")) {
			t.Fatal("posting secrets copied to case audit")
		}
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s2, e := Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	c, e = s2.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	rows2, e := s2.Records(c, now)
	if e != nil || len(rows2) != 1 {
		t.Fatal("recovery", e)
	}
	c, e = s2.Release(c.ID, actor, c.ETag(), "release-key", "request completed", now)
	if e != nil || c.State != "closed" {
		t.Fatal(c, e)
	}
	if _, e = os.Stat(s2.artifactDir(c.ID, "items")); !os.IsNotExist(e) {
		t.Fatal("copy retained", e)
	}
	if _, e = s2.Records(c, now); e != ErrExpired {
		t.Fatal("released copy readable", e)
	}
	if _, e = s2.Extend(c.ID, actor, c.ETag(), "extend-after-close", "reopen", domain.Time(now.Add(90*24*time.Hour).UnixNano()), now); e != ErrExpired {
		t.Fatal("resurrection", e)
	}
}
func TestCaseExpiryTamperingAndClockRollback(t *testing.T) {
	s, _, input, actor, now, r := fixture(t)
	input.Until = domain.Time(now.Add(time.Hour).UnixNano())
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.AuthorizeState(c.ID, c.ETag(), now.Add(-time.Nanosecond)); e != ErrExpired {
		t.Fatal("clock rollback", e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{r}, now)
	if e != nil {
		t.Fatal(e)
	}
	path := s.itemPath(c.ID, r.RecordID)
	raw, _ := os.ReadFile(path)
	raw = append(raw, ' ')
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Records(c, now); e == nil {
		t.Fatal("tampered hold accepted")
	}
	if _, e = s.AuthorizeState(c.ID, c.ETag(), now.Add(time.Hour)); e != ErrExpired {
		t.Fatal("expiry boundary", e)
	}
	if e = s.Sweep(now.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	c, e = s.Get(c.ID)
	if e != nil || c.State != "closed" {
		t.Fatal(c, e)
	}
	if _, e = os.Stat(filepath.Dir(path)); !os.IsNotExist(e) {
		t.Fatal("expired copy remained", e)
	}
}
func TestHoldIntentResumptionAndIndependentCases(t *testing.T) {
	s, key, input, actor, now, r := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	// intentを確定してコピー前で停止する。
	c.State = "preparing"
	c.Items = []Item{{Record: r.RecordID, Source: r.Proposal.Event.EventSHA, Expires: r.Expires, State: "pending"}}
	c, e = s.append(c, actor, "hold_intent", "preserve", nil, c.ETag(), "hold", struct {
		Purpose string `json:"purpose"`
	}{"preserve"}, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	s2, e := Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s2.Close()
	c, e = s2.resumeHold(c, actor, []app.AcceptedEvidence{r}, now)
	if e != nil || c.State != "active" {
		t.Fatal(c, e)
	}
	other, e := s2.Create(input, actor, `"evidence:new"`, "other", now)
	if e != nil {
		t.Fatal(e)
	}
	other, e = s2.Hold(other.ID, actor, other.ETag(), "other-hold", "preserve", []app.AcceptedEvidence{r}, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s2.Release(c.ID, actor, c.ETag(), "release", "close", now); e != nil {
		t.Fatal(e)
	}
	rows, e := s2.Records(other, now)
	if e != nil || len(rows) != 1 {
		t.Fatal("other case destroyed", e)
	}
	if _, _, e = s2.Query(other.ID, actor, other.ETag(), "invalid", "purpose", []string{"payload_base64"}, now); e != ErrInvalid {
		t.Fatal("unknown column", e)
	}
	// 案件メタデータは署名され、任意差替えを許可しない。
	names, _ := os.ReadDir(filepath.Join(s2.root, other.ID.String(), "control"))
	for _, name := range names {
		if strings.HasSuffix(name.Name(), ".wal") {
			info, e := os.Stat(filepath.Join(s2.root, other.ID.String(), "control", name.Name()))
			if e != nil || info.Mode().Perm() != 0600 {
				t.Fatal("private log mode", e)
			}
		}
	}
}

func TestQueryReplayAuditAndExportExpiry(t *testing.T) {
	s, _, input, actor, now, r := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{r}, now)
	if e != nil {
		t.Fatal(e)
	}
	etag := c.ETag()
	c, first, e := s.Query(c.ID, actor, etag, "same-query", "review", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	c, again, e := s.Query(c.ID, actor, etag, "same-query", "review", nil, now)
	if e != nil || len(first) != len(again) || c.Revision != 5 {
		t.Fatal("query replay must audit actual access", c, e)
	}
	if _, _, e = s.Query(c.ID, actor, etag, "same-query", "different-purpose", nil, now); e != ErrConflict {
		t.Fatal("query changed on replay", e)
	}
	if _, _, e = s.Query(c.ID, actor, etag, "new-query", "review", nil, now); e != ErrRevision {
		t.Fatal("CAS", e)
	}
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "export", "submit", nil, now)
	if e != nil {
		t.Fatal(e)
	}
	if _, f, _, e := s.Download(c.ID, v.ID, actor, c.ETag(), "download", "submit", now.Add(24*time.Hour)); e != ErrExpired {
		if f != nil {
			f.Close()
		}
		t.Fatal("24 hour boundary", e)
	}
	if e = s.Sweep(now.Add(24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.exportPath(c.ID, v.ID)); !os.IsNotExist(e) {
		t.Fatal("expired export retained", e)
	}
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if c.State != "active" {
		t.Fatal("export expiry shortened hold")
	}
	if rows, e := s.Records(c, now.Add(24*time.Hour)); e != nil || len(rows) != 1 {
		t.Fatal("held source expired early", e)
	}
}

func TestCreationCrashResumesSameSignedFrame(t *testing.T) {
	for _, point := range []string{"create:intent", "create:directory", "create:control", "create:complete"} {
		t.Run(point, func(t *testing.T) {
			s, key, input, actor, now, _ := fixture(t)
			s.checkpoint = func(got string) error {
				if got == point {
					return io.ErrUnexpectedEOF
				}
				return nil
			}
			id := s.IDFor(actor, "create-request")
			if _, e := s.Create(input, actor, `"evidence:new"`, "create-request", now); e == nil {
				t.Fatal("stop point ignored")
			}
			s.Close()
			reopened, e := Open(s.root, key)
			if e != nil {
				t.Fatal("resume", e)
			}
			defer reopened.Close()
			c, e := reopened.Get(id)
			if e != nil || c.Revision != 1 {
				t.Fatal("fixed result", c, e)
			}
			repeat, e := reopened.Create(input, actor, `"evidence:new"`, "create-request", now.Add(time.Second))
			if e != nil || repeat.ID != id {
				t.Fatal("retry", e)
			}
		})
	}
}

func TestPendingJobsResumeWithFreshRequestAndNoExpiryExtension(t *testing.T) {
	s, key, input, actor, now, r := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	s.checkpoint = func(point string) error {
		if point == "hold:intent" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	if _, e = s.Hold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{r}, now); e == nil {
		t.Fatal("hold stop ignored")
	}
	s.Close()
	reopened, e := Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	c, e = reopened.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c, e = reopened.Hold(c.ID, actor, c.ETag(), "resume-hold", "resume preservation", []app.AcceptedEvidence{r}, now)
	if e != nil || c.State != "active" {
		t.Fatal("fresh hold resume", c, e)
	}
	reopened.checkpoint = func(point string) error {
		if point == "export:file" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	if _, _, e = reopened.Generate(c.ID, actor, c.ETag(), "export", "submit", []string{"content"}, now); e == nil {
		t.Fatal("export stop ignored")
	}
	c, e = reopened.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	v := c.Exports[0]
	reopened.checkpoint = nil
	c, resumed, e := reopened.ResumeExport(c.ID, v.ID, actor, c.ETag(), "resume-export", "resume submission", now)
	if e != nil || resumed.ID != v.ID || resumed.Until != v.Until || resumed.State != "ready" {
		t.Fatal("fixed export resume", resumed, e)
	}
	// 監査Sync失敗時は照会結果を返さない。
	reopened.stopped = true
	if _, rows, e := reopened.Query(c.ID, actor, c.ETag(), "query", "review", []string{"content"}, now); e == nil || rows != nil {
		t.Fatal("audit failure disclosed data", e)
	}
}
func TestReadOnlyInspectionPreservesIncompleteCreation(t *testing.T) {
	s, key, input, actor, now, _ := fixture(t)
	s.checkpoint = func(point string) error {
		if point == "create:intent" {
			return io.ErrUnexpectedEOF
		}
		return nil
	}
	_, _ = s.Create(input, actor, `"evidence:new"`, "create", now)
	id := s.IDFor(actor, "create")
	s.Close()
	path := s.intentPath(id)
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = Inspect(s.root, key); e != store.ErrIncomplete {
		t.Fatal("read-only pending result", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("inspection changed intent", e)
	}
	if _, e = os.Stat(filepath.Join(s.root, id.String())); !os.IsNotExist(e) {
		t.Fatal("inspection created case")
	}
	reopened, e := Open(s.root, key)
	if e != nil {
		t.Fatal(e)
	}
	reopened.Close()
	if e = Inspect(s.root, key); e != nil {
		t.Fatal("completed inspection", e)
	}
}
