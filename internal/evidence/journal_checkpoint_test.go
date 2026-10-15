// 実ファイルの日末署名、重複防止、再読込と時計逆行拒否を検査する。
package evidence

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJournalCheckpointDiskBoundaryAndResume(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := domain.NewID()
	parent := t.TempDir()
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(parent, "20260928")
	j, e := OpenJournal(path, owner, 20260928, 10, key, testValidator)
	if e != nil {
		t.Fatal(e)
	}
	end := time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC)
	if j.CheckpointPending(end) {
		t.Fatal("empty source selected")
	}
	first, result := j.Append(domain.NewID(), "attempt", 1, func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	if _, e = j.Checkpoint(end.Add(-time.Nanosecond)); !errors.Is(e, ErrRetirementClock) {
		t.Fatal(e)
	}
	event, e := j.Checkpoint(end)
	if e != nil {
		t.Fatal(e)
	}
	p, e := VerifyJournalCheckpoint(event, key.Public().(ed25519.PublicKey))
	if e != nil || p.TerminalSHA != first.EventSHA || p.Count != 1 {
		t.Fatal(p, e)
	}
	duplicate, e := j.Checkpoint(end.Add(time.Hour))
	if e != nil || duplicate.EventSHA != event.EventSHA || len(j.Entries()) != 2 {
		t.Fatal("duplicate checkpoint", e)
	}
	_, result = j.Append(domain.NewID(), "attempt", 1, func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "late"})
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	if !j.CheckpointPending(end) {
		t.Fatal("late entry not selected")
	}
	later, e := j.Checkpoint(end)
	if e != nil || later.EventSHA == event.EventSHA {
		t.Fatal("late entry not checkpointed", e)
	}
	p, e = VerifyJournalCheckpoint(later, key.Public().(ed25519.PublicKey))
	if e != nil || p.Count != 3 {
		t.Fatal("count must include previous checkpoint", p, e)
	}
	if e = j.Close(); e != nil {
		t.Fatal(e)
	}
	j, e = OpenJournal(path, owner, 20260928, 10, key, testValidator)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	if _, e = j.Checkpoint(end.Add(-time.Nanosecond)); !errors.Is(e, ErrRetirementClock) {
		t.Fatal("clock rollback", e)
	}
	inspection, e := InspectJournal(path, owner, 20260928, 10, key, testValidator)
	if e != nil || inspection.MinimumReader != 55 || inspection.RequiredFloor != domain.Time(end.UnixNano()) {
		t.Fatal(inspection, e)
	}
}

func TestJournalCheckpointRejectsSignedWrongPrefix(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	owner := domain.NewID()
	p := JournalCheckpoint{Schema: "required-journal-checkpoint-v1", Owner: owner, Day: 20260928, Sequence: 2, TerminalSequence: 1, TerminalSHA: domain.Hash{1}, Count: 1, At: domain.Time(time.Date(2026, 9, 29, 0, 0, 0, 0, time.UTC).UnixNano())}
	raw, _ := json.Marshal(p)
	event, e := Seal(Source{owner, 20260928, 2}, domain.NewID(), "journal_checkpoint", raw, domain.Hash{2}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyJournalCheckpoint(event, key.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("signed wrong prefix accepted")
	}
}
