// 通常期限内の未受理提出が固定対象・先行監査・reader・一回取得を維持することを検査する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// rejectedExportFixture は実署名列の本文なし未受理接続を既存案件へ限定する。
func rejectedExportFixture(t *testing.T) (*Store, ed25519.PrivateKey, Case, domain.ID, time.Time, []app.RejectedEvidence) {
	return rejectedExportFixtureAt(t, 0)
}

// rejectedExportFixtureAt は明示した過去時刻の署名記録を作り、現在時計で期限後コピーを検査する。
func rejectedExportFixtureAt(t *testing.T, age time.Duration) (*Store, ed25519.PrivateKey, Case, domain.ID, time.Time, []app.RejectedEvidence) {
	t.Helper()
	s, key, input, actor, now, _ := fixture(t)
	now = now.Add(-age)
	at := domain.Time(now.Add(-6*24*time.Hour - 23*time.Hour).UnixNano())
	input.Scope.From, input.Scope.To = at-1, at+1
	identity := evidence.RequiredPostingIdentity{ThreadKey: 123, Type: "create", OperationID: domain.NewID(), ThreadSeq: 1, FrameSHA: domain.Hash{1}, Committed: at, ProposalID: domain.NewID(), ProposalSHA: domain.Hash{2}, DecisionID: domain.NewID(), DecisionSHA: domain.Hash{3}, Outcome: "not_accepted"}
	hash := sha256.Sum256(append(append([]byte("rejected_connection_v1"), identity.ProposalID[:]...), identity.DecisionID[:]...))
	var id domain.ID
	copy(id[:], hash[:16])
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	j, e := evidence.OpenJournal(filepath.Join(root, "20261001"), input.Scope.Board, 20261001, 10, key, app.PostingValidator(func([]byte) error { return nil }))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	_, result := j.Append(id, "rejected_connection", at, func(source evidence.Source) ([]byte, error) {
		return json.Marshal(map[string]any{"source_owner_id": source.Owner, "source_subkey": domain.U64(source.Subkey), "source_control_seq": domain.U64(source.Seq), "thread_key": identity.ThreadKey, "operation_id": identity.OperationID, "retention_until_ns": at + domain.Time(7*24*time.Hour), "posting_identity": identity, "connection": nil, "connection_missing_reason": "not_collected", "decision_at_ns": at, "recovered": true})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	rows, e := app.RejectedRecordsInRange([]*evidence.Journal{j}, func(domain.ID, domain.U64, domain.Time, domain.ID) bool { return true }, 100, domain.Time(now.UnixNano()))
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	c, e := s.Create(input, actor, `"evidence:new"`, "rejected-case", now)
	if e != nil {
		t.Fatal(e)
	}
	return s, key, c, actor, now, rows
}

func TestRejectedExportIntentRestartAndFrozenSources(t *testing.T) {
	s, key, c, actor, now, rows := rejectedExportFixture(t)
	var e error
	stop := errors.New("stop after intent")
	s.checkpoint = func(stage string) error {
		if stage == "export:intent" {
			return stop
		}
		return nil
	}
	c, _, e = s.GenerateRejected(c.ID, actor, c.ETag(), "rejected-export", "提出", []string{"connection"}, rows, now)
	if !errors.Is(e, stop) || len(c.Exports) != 1 || c.Exports[0].State != "preparing" {
		t.Fatal(c, e)
	}
	if c.Exports[0].Until != rows[0].Expires {
		t.Fatal("7d source deadline extended")
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
	v := c.Exports[0]
	if _, _, e = s.ResumeExport(c.ID, v.ID, actor, c.ETag(), "wrong-kind", "再開", now); !errors.Is(e, ErrInvalid) {
		t.Fatal("accepted path used for rejection", e)
	}
	if _, _, e = s.ResumeRejectedExport(c.ID, v.ID, actor, c.ETag(), "missing-source", "再開", nil, now); !errors.Is(e, ErrExpired) {
		t.Fatal("missing frozen source accepted", e)
	}
	c, e = s.Get(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	c, v, e = s.ResumeRejectedExport(c.ID, v.ID, actor, c.ETag(), "resume-rejected", "再開", rows, now)
	if e != nil || v.State != "ready" {
		t.Fatal(v, e)
	}
	raw, e := os.ReadFile(s.exportPath(c.ID, v.ID))
	if e != nil {
		t.Fatal(e)
	}
	m, e := VerifyZIP(bytes.NewReader(raw), int64(len(raw)), key.Public().(ed25519.PublicKey))
	if e != nil || m.RecordKind != "not_accepted" || m.Until != rows[0].Expires {
		t.Fatal(m, e)
	}
	if _, f, _, e := s.Download(c.ID, v.ID, actor, c.ETag(), "late-download", "取得", time.Unix(0, int64(v.Until))); !errors.Is(e, ErrExpired) {
		if f != nil {
			f.Close()
		}
		t.Fatal("expired source downloaded", e)
	}
}
