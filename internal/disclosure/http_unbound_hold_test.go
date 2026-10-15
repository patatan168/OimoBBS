// 操作なしHTTPの固定保全・再起動・選択ZIP・停止再開・期限回収を実ファイルで検証する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"os"
	"testing"
	"time"
)

func unboundHTTPFixture(t *testing.T) (*Store, ed25519.PrivateKey, Case, domain.ID, time.Time, domain.ID, evidence.Entry) {
	t.Helper()
	s, key, acceptedCase, actor, now, site, entry := httpHoldFixture(t)
	var p evidence.OptionalPayload
	if e := json.Unmarshal(entry.Payload, &p); e != nil {
		t.Fatal(e)
	}
	p.Record.Operation = nil
	p.Record.Outcome, p.Record.Status = "rejected", 403
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	event, e := evidence.Seal(evidence.Source{Owner: p.Owner, Subkey: uint64(p.Day), Seq: uint64(p.Seq)}, p.Record.ID, p.Record.Kind, raw, domain.Hash{}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	input := Case{Number: "HTTP", Reason: "HTTP観測", Scope: acceptedCase.Scope}
	input.Scope.Thread = 0
	c, e := s.Create(input, actor, `"evidence:new"`, "unbound-case", now)
	if e != nil {
		t.Fatal(e)
	}
	return s, key, c, actor, now, site, evidence.Entry{Event: event, Payload: raw}
}

func TestUnboundHTTPHoldZIPRestartAndCleanup(t *testing.T) {
	s, key, c, actor, now, site, entry := unboundHTTPFixture(t)
	c, e := s.HoldUnboundHTTP(c.ID, actor, c.ETag(), "unbound-hold", "保全", site, []evidence.Entry{entry}, now)
	if e != nil || c.State != "active" || !c.HTTP.Unbound {
		t.Fatal(c, e)
	}
	if e = InspectVersion(s.root, key, 56); e == nil {
		t.Fatal("reader56 accepted unbound hold")
	}
	if e = InspectVersion(s.root, key, 57); e != nil {
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
	rows, e := s.HTTPRecords(c, now.Add(8*24*time.Hour))
	if e != nil || len(rows) != 1 {
		t.Fatal("source expiry applied to case copy", rows, e)
	}
	if _, e = s.PrepareHTTPHold(c.ID, actor, c.ETag(), "replace-mode", "保全", site, nil, now); !errors.Is(e, ErrConflict) {
		t.Fatal("mode changed", e)
	}
	for i, columns := range [][]string{nil, {"connection"}} {
		var v Export
		c, v, e = s.Generate(c.ID, actor, c.ETag(), string(rune('a'+i))+"-zip", "提出", columns, now)
		if e != nil || v.Kind != "http_observation" || v.State != "ready" {
			t.Fatal(v, e)
		}
		raw, e := readArtifact(s.exportPath(c.ID, v.ID))
		if e != nil {
			t.Fatal(e)
		}
		m, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
		if e != nil || m.RecordKind != "http_observation" || m.Count != 1 || len(m.Sources) != 1 || m.Completeness != "partial_observation" {
			t.Fatal(m, e)
		}
		records := zipRecords(t, raw)
		if bytes.Contains(records, []byte(`"peer"`)) != (i == 1) || bytes.Contains(records, []byte("PRIVATE_BODY")) || bytes.Contains(records, []byte("payload_base64")) {
			t.Fatal("projection leaked", string(records))
		}
	}
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Generate(c.ID, actor, c.ETag(), "body", "本文拒否", []string{"content"}, now); !errors.Is(e, ErrInvalid) {
		t.Fatal("body column accepted", e)
	}
	c, e = s.Release(c.ID, actor, c.ETag(), "release-http", "解除", now)
	if e != nil || c.HTTP.State != "removed" {
		t.Fatal(c, e)
	}
	if _, e = os.Stat(s.artifactDir(c.ID, "http")); !os.IsNotExist(e) {
		t.Fatal("copy retained", e)
	}
	if _, e = os.Stat(s.artifactDir(c.ID, "exports")); !os.IsNotExist(e) {
		t.Fatal("ZIP retained", e)
	}
}

func TestUnboundHTTPStopResumeAndZIPFixedSelection(t *testing.T) {
	s, key, c, actor, now, site, entry := unboundHTTPFixture(t)
	injected := errors.New("stop after copy")
	s.checkpoint = func(at string) error {
		if at == "http_hold:file" {
			return injected
		}
		return nil
	}
	before := c.ETag()
	c, e := s.HoldUnboundHTTP(c.ID, actor, before, "fixed-http", "保全", site, []evidence.Entry{entry}, now)
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	root := s.root
	s.Close()
	s, e = Open(root, key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	c, e = s.HoldUnboundHTTP(c.ID, actor, before, "fixed-http", "保全", site, nil, now)
	if e != nil || c.State != "active" {
		t.Fatal(c, e)
	}
	s.checkpoint = func(at string) error {
		if at == "export:intent" {
			return injected
		}
		return nil
	}
	c, _, e = s.Generate(c.ID, actor, c.ETag(), "fixed-zip", "提出", nil, now)
	if !errors.Is(e, injected) {
		t.Fatal(e)
	}
	pending := c.Exports[len(c.Exports)-1]
	s.checkpoint = nil
	c, v, e := s.ResumeExport(c.ID, pending.ID, actor, c.ETag(), "resume-zip", "再開", now)
	if e != nil || v.State != "ready" || v.HTTPSelection != pending.HTTPSelection || v.Until != pending.Until {
		t.Fatal(v, e)
	}
	if e = s.Sweep(time.Unix(0, int64(c.Until))); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(s.artifactDir(c.ID, "http")); !os.IsNotExist(e) {
		t.Fatal("expired copy retained", e)
	}
}
