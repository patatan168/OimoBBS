// HTTP保全copyの固定集合・停止再開・元期限後照会・選択ZIPと解除回収を実fileで検査する。
package disclosure

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func httpHoldFixture(t *testing.T) (*Store, ed25519.PrivateKey, Case, domain.ID, time.Time, domain.ID, evidence.Entry) {
	t.Helper()
	s, key, input, actor, now, accepted := fixture(t)
	c, e := s.Create(input, actor, `"evidence:new"`, "create", now)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.Hold(c.ID, actor, c.ETag(), "hold", "preserve", []app.AcceptedEvidence{accepted}, now)
	if e != nil {
		t.Fatal(e)
	}
	site := domain.NewID()
	r := evidence.OptionalRecord{Schema: "optional-http-v1", ID: domain.NewID(), Site: site, Board: &accepted.Board, Boot: domain.NewID(), Connection: domain.NewID(), Request: domain.NewID(), Operation: &accepted.Operation, Received: accepted.Committed, Finished: accepted.Committed + 100, Until: accepted.Committed + domain.Time(evidence.OptionalRetention), Peer: evidence.Endpoint{IP: "127.0.0.1", Port: 12345}, Local: evidence.Endpoint{IP: "127.0.0.1", Port: 8080}, Method: "POST", Route: "legacy_post", Kind: "response", Outcome: "accepted", Status: 200, UAStatus: "unavailable", FinishStage: "handler_return", HTTPVersion: "HTTP/1.1"}
	day, _ := strconv.ParseUint(time.Unix(0, int64(r.Received)).UTC().Format("20060102"), 10, 64)
	p := evidence.OptionalPayload{Owner: evidence.OptionalOwner(site), Day: domain.U64(day), Seq: 1, Record: r}
	raw, _ := json.Marshal(p)
	event, e := evidence.Seal(evidence.Source{Owner: p.Owner, Subkey: day, Seq: 1}, r.ID, "response", raw, domain.Hash{}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	return s, key, c, actor, now, site, evidence.Entry{Event: event, Payload: raw}
}

func zipRecords(t *testing.T, raw []byte) []byte {
	t.Helper()
	z, e := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	return csvZIPTestJSON(t, z)
}

func TestHTTPHoldLifecycleProjectionAndCleanup(t *testing.T) {
	s, key, c, actor, now, site, entry := httpHoldFixture(t)
	before := c.ETag()
	c, e := s.HoldHTTP(c.ID, actor, before, "http-hold", "preserve HTTP", site, []evidence.Entry{entry}, now)
	if e != nil || c.HTTP == nil || c.HTTP.State != "active" || len(c.HTTP.Items) != 1 {
		t.Fatal(c, e)
	}
	again, e := s.HoldHTTP(c.ID, actor, before, "http-hold", "preserve HTTP", site, nil, now)
	if e != nil || again.Revision != c.Revision {
		t.Fatal("hold replay", again, e)
	}
	rows, e := s.HTTPRecords(c, now.Add(8*24*time.Hour))
	if e != nil || len(rows) != 1 || rows[0].Record.ID != entry.Event.RecordID {
		t.Fatal("original expiry applied to copy", rows, e)
	}
	c, data, e := s.Query(c.ID, actor, c.ETag(), "http-query", "read", []string{"connection"}, now)
	if e != nil || len(data) != 1 {
		t.Fatal(data, e)
	}
	raw, _ := json.Marshal(data)
	if !bytes.Contains(raw, []byte(entry.Event.RecordID.String())) || !bytes.Contains(raw, []byte("partial_observation")) || bytes.Contains(raw, []byte("signature_base64")) || bytes.Contains(raw, []byte("payload_base64")) {
		t.Fatal("projection", string(raw))
	}
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "http-export", "export", []string{"connection"}, now)
	if e != nil || v.HTTPSelection == (domain.Hash{}) || v.State != "ready" {
		t.Fatal(v, e)
	}
	b, e := readArtifact(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := VerifyZIP(bytes.NewReader(b), int64(len(b)), key.Public().(ed25519.PublicKey))
	if e != nil || len(m.Sources) != 2 {
		t.Fatal(m, e)
	}
	raw = zipRecords(t, b)
	if !bytes.Contains(raw, []byte(entry.Event.RecordID.String())) || bytes.Contains(raw, []byte("PRIVATE_BODY")) || bytes.Contains(raw, []byte("signature_base64")) {
		t.Fatal("ZIP selection", string(raw))
	}
	c, v, e = s.Generate(c.ID, actor, c.ETag(), "content-export", "content", []string{"content"}, now)
	if e != nil || v.HTTPSelection != (domain.Hash{}) {
		t.Fatal(v, e)
	}
	b, e = readArtifact(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	raw = zipRecords(t, b)
	if bytes.Contains(raw, []byte("optional_http")) || bytes.Contains(raw, []byte(entry.Event.RecordID.String())) {
		t.Fatal("unselected HTTP leaked", string(raw))
	}
	if e := InspectVersion(s.root, key, 40); e == nil {
		t.Fatal("reader40 accepted HTTP case")
	}
	if e := InspectVersion(s.root, key, 41); e != nil {
		t.Fatal(e)
	}
	root := s.root
	s.Close()
	s, e = Open(root, key)
	if e != nil {
		t.Fatal("restart", e)
	}
	defer s.Close()
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if rows, e := s.HTTPRecords(c, now.Add(8*24*time.Hour)); e != nil || len(rows) != 1 {
		t.Fatal("restart copy", rows, e)
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "release", "done", now)
	if e != nil || c.HTTP.State != "removed" {
		t.Fatal(c, e)
	}
	if _, e := os.Stat(s.artifactDir(c.ID, "http")); !os.IsNotExist(e) {
		t.Fatal("HTTP copy retained", e)
	}
	if _, e := s.HTTPRecords(c, now); e == nil {
		t.Fatal("released copy disclosed")
	}
}

func TestHTTPHoldResumeFixedIntentAndMissingSource(t *testing.T) {
	for _, stop := range []string{"http_hold:intent", "http_hold:file"} {
		t.Run(stop, func(t *testing.T) {
			s, key, c, actor, now, site, entry := httpHoldFixture(t)
			before := c.ETag()
			injected := errors.New("stopped")
			s.checkpoint = func(at string) error {
				if at == stop {
					return injected
				}
				return nil
			}
			c, e := s.HoldHTTP(c.ID, actor, before, "http-key", "hold", site, []evidence.Entry{entry}, now)
			if !errors.Is(e, injected) {
				t.Fatal(e)
			}
			if e := InspectVersion(s.root, key, 41); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("pending check", e)
			}
			root := s.root
			s.Close()
			s, e = Open(root, key)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			current, err := s.Get(c.ID)
			if err != nil {
				t.Fatal(err)
			}
			ids, err := s.HTTPSourceIDs(current, now)
			expected := 1
			if stop == "http_hold:file" {
				expected = 0
			}
			if err != nil || len(ids) != expected {
				t.Fatal("unneeded source queried", ids, err)
			}
			c, e = s.HoldHTTP(c.ID, actor, before, "http-key", "hold", site, nil, now.Add(8*24*time.Hour))
			if e != nil {
				t.Fatal(e)
			}
			if len(c.HTTP.Items) != 1 || c.HTTP.Items[0].Record != entry.Event.RecordID {
				t.Fatal("fixed scope replaced")
			}
			want := "partial"
			if stop == "http_hold:file" {
				want = "active"
			}
			if c.HTTP.State != want {
				t.Fatal(c.HTTP.State, want)
			}
			rows, e := s.HTTPRecords(c, now.Add(8*24*time.Hour))
			if e != nil || (stop == "http_hold:file") != (len(rows) == 1) {
				t.Fatal(rows, e)
			}
			if e := s.Sweep(time.Unix(0, int64(c.Until))); e != nil {
				t.Fatal(e)
			}
			if _, e := os.Stat(s.artifactDir(c.ID, "http")); !os.IsNotExist(e) {
				t.Fatal("expired copy retained", e)
			}
		})
	}
}

func TestHTTPHoldRejectsMismatchAndTamperedCopy(t *testing.T) {
	s, _, c, actor, now, site, entry := httpHoldFixture(t)
	if _, e := s.HoldHTTP(c.ID, actor, c.ETag(), "foreign-site", "hold", domain.NewID(), []evidence.Entry{entry}, now); e == nil {
		t.Fatal("foreign site accepted")
	}
	if _, e := s.HoldHTTP(c.ID, actor, c.ETag(), "duplicate", "hold", site, []evidence.Entry{entry, entry}, now); e == nil {
		t.Fatal("duplicate accepted")
	}
	bad := evidence.Entry{Event: entry.Event, Payload: slices.Clone(entry.Payload)}
	bad.Payload[0] = '!'
	if _, e := s.HoldHTTP(c.ID, actor, c.ETag(), "bad", "hold", site, []evidence.Entry{bad}, now); e == nil {
		t.Fatal("tamper accepted")
	}
	c, e := s.HoldHTTP(c.ID, actor, c.ETag(), "valid", "hold", site, []evidence.Entry{entry}, now)
	if e != nil {
		t.Fatal(e)
	}
	path := s.httpPath(c.ID, entry.Event.RecordID)
	b, e := readArtifact(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(strings.Replace(string(b), `"kind":"response"`, `"kind":"receipt"`, 1)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.HTTPRecords(c, now); e == nil {
		t.Fatal("corrupt copy disclosed")
	}
}

func TestHTTPHoldPreservesNoncanonicalPayloadBytes(t *testing.T) {
	s, key, c, actor, now, site, entry := httpHoldFixture(t)
	var formatted bytes.Buffer
	if e := json.Indent(&formatted, entry.Payload, "", "  "); e != nil {
		t.Fatal(e)
	}
	entry.Payload = formatted.Bytes()
	var p evidence.OptionalPayload
	if e := json.Unmarshal(entry.Payload, &p); e != nil {
		t.Fatal(e)
	}
	var e error
	entry.Event, e = evidence.Seal(evidence.Source{Owner: p.Owner, Subkey: uint64(p.Day), Seq: uint64(p.Seq)}, entry.Event.RecordID, entry.Event.Kind, entry.Payload, entry.Event.PreviousSHA, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	c, e = s.HoldHTTP(c.ID, actor, c.ETag(), "exact-bytes", "preserve", site, []evidence.Entry{entry}, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := readArtifact(s.httpPath(c.ID, entry.Event.RecordID))
	if e != nil {
		t.Fatal(e)
	}
	var stored evidence.Event
	if e := json.Unmarshal(raw, &stored); e != nil {
		t.Fatal(e)
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(stored.Payload)
	if e != nil || !bytes.Equal(payload, entry.Payload) {
		t.Fatal("signed payload reformatted", e)
	}
	if rows, e := s.HTTPRecords(c, now); e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
}

func TestHTTPHoldUnknownAndMissingArtifacts(t *testing.T) {
	for _, mode := range []string{"unknown", "missing", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			s, key, c, actor, now, site, entry := httpHoldFixture(t)
			c, e := s.HoldHTTP(c.ID, actor, c.ETag(), "hold-http", "hold", site, []evidence.Entry{entry}, now)
			if e != nil {
				t.Fatal(e)
			}
			root := s.root
			path := s.httpPath(c.ID, entry.Event.RecordID)
			if mode == "unknown" {
				path = filepath.Join(s.artifactDir(c.ID, "http"), "unknown.json")
				if e = os.WriteFile(path, []byte("preserve-unknown"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "missing" || mode == "symlink" {
				if e = os.Remove(path); e != nil {
					t.Fatal(e)
				}
			}
			if mode == "symlink" {
				if e = os.Symlink("missing", path); e != nil {
					t.Fatal(e)
				}
			}
			s.Close()
			if e := InspectVersion(root, key, 41); e == nil {
				t.Fatal("invalid copy set accepted by check")
			}
			if reopened, e := Open(root, key); e == nil {
				reopened.Close()
				t.Fatal("invalid copy set accepted by startup")
			}
			if mode == "unknown" {
				raw, e := os.ReadFile(path)
				if e != nil || string(raw) != "preserve-unknown" {
					t.Fatal("unknown artifact modified", e)
				}
			}
		})
	}
}

func TestHTTPExportResumeKeepsOriginalSelection(t *testing.T) {
	s, _, c, actor, now, site, entry := httpHoldFixture(t)
	injected := errors.New("stop after export intent")
	s.checkpoint = func(at string) error {
		if at == "export:intent" {
			return injected
		}
		return nil
	}
	c, _, e := s.Generate(c.ID, actor, c.ETag(), "before-http", "export", []string{"connection"}, now)
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	export := c.Exports[0]
	s.checkpoint = nil
	c, e = s.HoldHTTP(c.ID, actor, c.ETag(), "later-http", "hold", site, []evidence.Entry{entry}, now)
	if e != nil {
		t.Fatal(e)
	}
	c, export, e = s.ResumeExport(c.ID, export.ID, actor, c.ETag(), "resume", "resume", now)
	if e != nil || export.State != "ready" {
		t.Fatal(export, e)
	}
	raw, e := readArtifact(s.exportPath(c.ID, export.ID))
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(zipRecords(t, raw), []byte("optional_http")) {
		t.Fatal("resumed export added later HTTP hold")
	}
}

// 部分保全の欠落をZIPへ明記し、途中のコピー追加で古い生成intentの集合をすり替えない。
func TestHTTPHoldPartialExportSelectionConflict(t *testing.T) {
	s, key, c, actor, now, site, entry := httpHoldFixture(t)
	before := c.ETag()
	injected := errors.New("stop")
	s.checkpoint = func(at string) error {
		if at == "http_hold:intent" {
			return injected
		}
		return nil
	}
	c, e := s.HoldHTTP(c.ID, actor, before, "partial-http", "hold", site, []evidence.Entry{entry}, now)
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	s.checkpoint = nil
	c, e = s.HoldHTTP(c.ID, actor, before, "partial-http", "hold", site, nil, now)
	if e != nil || c.HTTP.State != "partial" {
		t.Fatal(c, e)
	}
	c, v, e := s.Generate(c.ID, actor, c.ETag(), "missing-export", "export", []string{"connection"}, now)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := readArtifact(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
	if e != nil || len(m.Missing) != 1 || m.Missing[0] != entry.Event.RecordID {
		t.Fatal("missing HTTP absent", m, e)
	}
	s.checkpoint = func(at string) error {
		if at == "export:intent" {
			return injected
		}
		return nil
	}
	c, _, e = s.Generate(c.ID, actor, c.ETag(), "fixed-export", "export", []string{"connection"}, now)
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	pending := c.Exports[len(c.Exports)-1]
	s.checkpoint = nil
	c, e = s.HoldHTTP(c.ID, actor, c.ETag(), "resume-http", "resume", site, []evidence.Entry{entry}, now)
	if e != nil || c.HTTP.State != "active" {
		t.Fatal(c, e)
	}
	_, _, e = s.ResumeExport(c.ID, pending.ID, actor, c.ETag(), "resume-export", "resume", now)
	if !errors.Is(e, ErrConflict) {
		t.Fatal("changed HTTP selection substituted", e)
	}
}
