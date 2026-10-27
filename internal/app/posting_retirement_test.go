// 必須原本の実file回収、保全予約拒否、停止後の署名連鎖と本文なし対応情報を検査する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type retirementFixture struct {
	journal  *evidence.Journal
	key      ed25519.PrivateKey
	owner    domain.ID
	path     string
	until    domain.Time
	identity evidence.RequiredPostingIdentity
	entries  []evidence.Entry
}

func newRetirementFixture(t *testing.T) retirementFixture {
	t.Helper()
	owner, frame, now := postingFixture(t)
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
	path := filepath.Join(root, "20231114")
	j, e := evidence.OpenJournal(path, owner, 20231114, 10, key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	p, e := OpenPosting(threads, owner, 1700000000, []*evidence.Journal{j}, j, now)
	if e != nil {
		t.Fatal(e)
	}
	if got := p.Post(context.Background(), frame, []byte(`{"fixture":true}`), now); got.Status != store.Durable {
		t.Fatal(got)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	entries := j.Entries()
	i, e := PostingRetirementIdentity(entries[0], entries[1])
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = j.Close() })
	return retirementFixture{j, key, owner, path, postRetention(now), i, entries}
}

func (f retirementFixture) selectIdentity(e evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
	i := f.identity
	return &i, nil
}

func noRetirementHold(domain.ID, domain.Time) (bool, error) { return false, nil }

func TestRequiredRetirementExpiryAndReservation(t *testing.T) {
	f := newRetirementFixture(t)
	if n, e := f.journal.PruneRequired(f.until-1, f.selectIdentity, noRetirementHold, nil); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	failure := errors.New("reservation owner unavailable")
	before := retirementFiles(t, f.path)
	if n, e := f.journal.PruneRequired(f.until, f.selectIdentity, func(domain.ID, domain.Time) (bool, error) { return false, failure }, nil); !errors.Is(e, failure) || n != 0 {
		t.Fatal(n, e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
		t.Fatal("reservation failure changed source files")
	}
	if n, e := f.journal.PruneRequired(f.until, f.selectIdentity, nil, nil); e == nil || n != 0 {
		t.Fatal("missing reservation check accepted")
	}
	protected := f.identity.ProposalID
	if n, e := f.journal.PruneRequired(f.until, f.selectIdentity, func(id domain.ID, _ domain.Time) (bool, error) { return id == protected, nil }, nil); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	if len(f.journal.Entries()) != 2 || f.journal.Entries()[0].Event != f.entries[0].Event {
		t.Fatal("protected original changed")
	}
	if n, e := f.journal.PruneRequired(f.until, f.selectIdentity, noRetirementHold, nil); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	retired, e := f.journal.RequiredRetirements()
	if e != nil || len(retired) != 2 {
		t.Fatal(retired, e)
	}
	for _, r := range retired {
		if r.Identity != f.identity || r.Envelope.Payload != "" {
			t.Fatal("bodyless correspondence differs")
		}
	}
	assertRetiredPayloadAbsent(t, f)
	if n, e := f.journal.PruneRequired(f.until, f.selectIdentity, noRetirementHold, nil); e != nil || n != 0 {
		t.Fatal("repeated GC changed chain", n, e)
	}
}

func TestRequiredRetirementInterruptedRecovery(t *testing.T) {
	for _, stage := range []string{"required:removed", "required:snapshot_intent", "required:snapshot_current"} {
		t.Run(stage, func(t *testing.T) {
			f := newRetirementFixture(t)
			stop := errors.New("simulated interruption")
			n, e := f.journal.PruneRequired(f.until, f.selectIdentity, noRetirementHold, func(at string) error {
				if at == stage {
					return stop
				}
				return nil
			})
			if n != 2 || !errors.Is(e, stop) {
				t.Fatal(n, e)
			}
			if _, e = f.journal.RequiredRetirements(); !errors.Is(e, store.ErrIncomplete) {
				t.Fatal("stopped source returned metadata", e)
			}
			if e = f.journal.Close(); e != nil {
				t.Fatal(e)
			}
			before := retirementFiles(t, f.path)
			inspection, e := evidence.InspectJournal(f.path, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture))
			if e != nil || inspection.Sequence != 3 || inspection.RequiredRetirements != 2 || inspection.RequiredFloor != f.until {
				t.Fatal("read-only signed inspection", inspection, e)
			}
			if !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
				t.Fatal("read-only inspection resumed reclamation")
			}
			j, e := evidence.OpenJournal(f.path, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture))
			if e != nil {
				t.Fatal(e)
			}
			defer j.Close()
			retired, e := j.RequiredRetirements()
			if e != nil || len(retired) != 2 || len(j.Entries()) != 1 {
				t.Fatal(retired, e)
			}
			for _, r := range retired {
				if r.Identity != f.identity {
					t.Fatal("recovery correspondence changed")
				}
			}
			assertRetiredPayloadAbsent(t, f)
			if _, e = os.Stat(filepath.Join(f.path, ".optional-prune.snapshot")); !os.IsNotExist(e) {
				t.Fatal("reclamation intent remained", e)
			}
			called := false
			_, result := j.Append(f.identity.ProposalID, "evidence_proposal", f.until, func(evidence.Source) ([]byte, error) {
				called = true
				return nil, errors.New("retired ID was reused")
			})
			if result.Status != store.NotWritten || called {
				t.Fatal(result)
			}
		})
	}
}

func TestRequiredRetirementRejectsWrongCorrespondence(t *testing.T) {
	for _, mutation := range []string{"operation", "type", "frame", "deadline", "proposal", "decision", "outcome"} {
		t.Run(mutation, func(t *testing.T) {
			f := newRetirementFixture(t)
			i := f.identity
			switch mutation {
			case "operation":
				i.OperationID = domain.NewID()
			case "type":
				i.Type = "append"
			case "frame":
				i.FrameSHA[0] ^= 1
			case "deadline":
				i.Committed++
			case "proposal":
				i.ProposalID = domain.NewID()
			case "decision":
				i.DecisionSHA[0] ^= 1
			case "outcome":
				i.Outcome = "not_accepted"
			}
			before := retirementFiles(t, f.path)
			if n, e := f.journal.PruneRequired(f.until, func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) { return &i, nil }, noRetirementHold, nil); e == nil || n != 0 {
				t.Fatal("bad correspondence accepted", n, e)
			}
			if !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
				t.Fatal("invalid selection changed source")
			}
		})
	}
}

func TestPostingRetirementProjectionRejectsUnverifiedPair(t *testing.T) {
	f := newRetirementFixture(t)
	proposal, decision := f.entries[0], f.entries[1]
	var d postingDecision
	if e := json.Unmarshal(decision.Payload, &d); e != nil {
		t.Fatal(e)
	}
	d.OperationID = domain.NewID()
	decision.Payload, _ = json.Marshal(d)
	if _, e := PostingRetirementIdentity(proposal, decision); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal(e)
	}
	proposal.Payload = []byte(`{"secret":"wrong payload"}`)
	if _, e := PostingRetirementIdentity(proposal, f.entries[1]); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal(e)
	}
}

func TestRequiredRetirementRefusesStandaloneTombstone(t *testing.T) {
	f := newRetirementFixture(t)
	before := retirementFiles(t, f.path)
	called := false
	_, result := f.journal.Append(domain.NewID(), "tombstone", f.until, func(evidence.Source) ([]byte, error) {
		called = true
		return nil, errors.New("standalone tombstone must not be built")
	})
	if result.Status != store.NotWritten || called || !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
		t.Fatal("standalone tombstone changed chain", result, called)
	}
}

func TestRequiredRetirementBoundedBatchesAndAppend(t *testing.T) {
	f := newRetirementFixture(t)
	identities := map[domain.ID]evidence.RequiredPostingIdentity{}
	for range 70 {
		i := appendRetirementPair(t, f)
		identities[i.ProposalID] = i
		identities[i.DecisionID] = i
	}
	selectIdentity := func(entry evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
		i, ok := identities[entry.Event.RecordID]
		if !ok {
			return nil, nil
		}
		return &i, nil
	}
	held := func(id domain.ID, _ domain.Time) (bool, error) {
		return id == f.identity.ProposalID || id == f.identity.DecisionID, nil
	}
	for _, want := range []int{128, 12, 0} {
		if n, e := f.journal.PruneRequired(f.until, selectIdentity, held, nil); e != nil || n != want {
			t.Fatal(n, want, e)
		}
	}
	retired, e := f.journal.RequiredRetirements()
	if e != nil || len(retired) != 140 {
		t.Fatal(len(retired), e)
	}
	if got := f.journal.Entries(); len(got) != 4 || got[0].Event != f.entries[0].Event || got[1].Event != f.entries[1].Event {
		t.Fatal("held original signature changed")
	}
	appendRetirementPair(t, f)
	entries := f.journal.Entries()
	var proposal postingProposal
	if e = json.Unmarshal(entries[len(entries)-2].Payload, &proposal); e != nil || proposal.Seq != 145 {
		t.Fatal("source sequence did not include removed records", proposal.Seq, e)
	}
	if e = f.journal.Close(); e != nil {
		t.Fatal(e)
	}
	j, e := evidence.OpenJournal(f.path, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	retired, e = j.RequiredRetirements()
	if e != nil || len(retired) != 140 || len(j.Entries()) != 6 {
		t.Fatal(len(retired), e)
	}
}

// appendRetirementPair は別操作IDの有効frameを用いて、同じ所有列へ受理対応を保存する。
func appendRetirementPair(t *testing.T, f retirementFixture) evidence.RequiredPostingIdentity {
	t.Helper()
	var p postingProposal
	var d postingDecision
	if e := json.Unmarshal(f.entries[0].Payload, &p); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(f.entries[1].Payload, &d); e != nil {
		t.Fatal(e)
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(p.Frame)
	if e != nil {
		t.Fatal(e)
	}
	frame, _, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	frame.Records[0].ID = domain.NewID()
	raw, e = store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	p.OperationID, p.FrameSHA, p.Frame = frame.Records[0].ID, sha256.Sum256(raw), base64.StdEncoding.EncodeToString(raw)
	proposal, result := f.journal.Append(domain.NewID(), "evidence_proposal", p.Committed, func(src evidence.Source) ([]byte, error) {
		p.Owner, p.Day, p.Seq = src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq)
		return json.Marshal(p)
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	d.OperationID, d.FrameSHA, d.ProposalID, d.ProposalSHA = p.OperationID, p.FrameSHA, proposal.RecordID, proposal.EventSHA
	_, result = f.journal.Append(domain.NewID(), "evidence_decision", d.Decided, func(src evidence.Source) ([]byte, error) {
		d.Owner, d.Day, d.Seq = src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq)
		return json.Marshal(d)
	})
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	entries := f.journal.Entries()
	i, e := PostingRetirementIdentity(entries[len(entries)-2], entries[len(entries)-1])
	if e != nil {
		t.Fatal(e)
	}
	return i
}

func retirementFiles(t *testing.T, path string) map[string][]byte {
	t.Helper()
	entries, e := os.ReadDir(path)
	if e != nil {
		t.Fatal(e)
	}
	result := map[string][]byte{}
	for _, entry := range entries {
		raw, e := os.ReadFile(filepath.Join(path, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		result[entry.Name()] = raw
	}
	return result
}

func assertRetiredPayloadAbsent(t *testing.T, f retirementFixture) {
	t.Helper()
	for name, raw := range retirementFiles(t, f.path) {
		for _, original := range f.entries {
			if bytes.Contains(raw, []byte(original.Event.Payload)) || bytes.Contains(raw, original.Payload) {
				t.Fatal("original payload remains in", name)
			}
		}
	}
	if _, e := os.Stat(filepath.Join(f.path, "control-000001.wal")); !os.IsNotExist(e) {
		t.Fatal("old original WAL remains", e)
	}
}
