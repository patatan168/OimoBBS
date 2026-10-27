// 原本回収後の署名照合・本文非復元と、公開回収証明/carry欠落の拒否を実fileで検査する。
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func retiredRecoveryFixture(t *testing.T, mode string) (retirementFixture, string, BodyReclamation, BodyCarry) {
	t.Helper()
	return retiredRecoveryFixtureWithDelay(t, mode, 0)
}

func retiredRecoveryFixtureWithDelay(t *testing.T, mode string, delay domain.Time) (retirementFixture, string, BodyReclamation, BodyCarry) {
	t.Helper()
	f := newRetirementFixture(t)
	parent := filepath.Join(filepath.Dir(f.path), "threads")
	p, e := OpenPosting(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.identity.Committed)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := p.PrepareBodyReclamation(context.Background(), domain.NewID(), "expire", f.until, f.key)
	if e != nil {
		t.Fatal(e)
	}
	carry, e := p.ExportBodyCarry(proof.Floor, proof.CarryAt())
	if e != nil {
		t.Fatal(e)
	}
	if e = p.RetireBody(proof); e != nil {
		t.Fatal(e)
	}
	if e = store.RemoveReclaimedBody(context.Background(), filepath.Join(parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	held := func(id domain.ID, _ domain.Time) (bool, error) {
		return mode == "proposal" && id == f.identity.DecisionID || mode == "decision" && id == f.identity.ProposalID, nil
	}
	want := 2
	if mode != "both" {
		want = 1
	}
	if n, e := f.journal.PruneRequired(f.until+delay, f.selectIdentity, held, nil); e != nil || n != want {
		t.Fatal(n, e)
	}
	if e = f.journal.Close(); e != nil {
		t.Fatal(e)
	}
	f.journal, e = evidence.OpenJournal(f.path, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = f.journal.Close() })
	return f, parent, proof, carry
}

func TestRetiredRecoveryUsesSignedRemovalTimeFloor(t *testing.T) {
	for _, mode := range []string{"both", "proposal", "decision"} {
		t.Run(mode, func(t *testing.T) {
			delay := domain.Time(24 * time.Hour)
			f, parent, proof, carry := retiredRecoveryFixtureWithDelay(t, mode, delay)
			floor := f.until + delay
			if got, e := f.journal.RequiredRetirementFloor(); e != nil || got != floor {
				t.Fatal("signed removal floor not restored", got, e)
			}
			before := retirementFiles(t, f.path)
			public := f.key.Public().(ed25519.PublicKey)
			// 6暦月は既に満了しているが、実際の回収時刻より前へ戻した起動は拒否する。
			if p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, floor-1, proof, &carry, public); !errors.Is(e, ErrEvidenceGap) || !errors.Is(e, evidence.ErrRetirementClock) || p != nil {
				t.Fatal("single-key recovery rewound removal time", e)
			}
			proofs := map[uint64]BodyReclamation{1700000000: proof}
			carries := map[uint64]BodyCarry{1700000000: carry}
			if p, e := OpenPostingsWithRetiredOriginals(parent, f.owner, []uint64{1}, []*evidence.Journal{f.journal}, f.journal, floor-1, proofs, carries, public); !errors.Is(e, ErrEvidenceGap) || !errors.Is(e, evidence.ErrRetirementClock) || p != nil {
				t.Fatal("board recovery rewound removal time", e)
			}
			called := false
			if n, e := f.journal.PruneRequired(floor-1, func(evidence.Entry) (*evidence.RequiredPostingIdentity, error) { called = true; return nil, nil }, noRetirementHold, nil); !errors.Is(e, evidence.ErrRetirementClock) || n != 0 || called {
				t.Fatal("GC moved below signed removal floor", n, e, called)
			}
			if !sameRetirementFiles(before, retirementFiles(t, f.path)) {
				t.Fatal("rejected clock changed original files")
			}
			p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, floor, proof, &carry, public)
			if e != nil {
				t.Fatal("exact removal floor refused", e)
			}
			if !p.Reclaimed() || p.Snapshot(floor) != nil {
				t.Fatal("recovery restored public body")
			}
			p.Close()
		})
	}
}

func TestRetiredRecoveryFloorSurvivesNewActiveJournal(t *testing.T) {
	f, parent, proof, carry := retiredRecoveryFixtureWithDelay(t, "both", domain.Time(24*time.Hour))
	active, e := evidence.OpenJournal(filepath.Join(filepath.Dir(f.path), "20240515"), f.owner, 20240515, 10, f.key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer active.Close()
	if floor, e := active.RequiredRetirementFloor(); e != nil || floor != 0 {
		t.Fatal("empty active journal has unexpected floor", floor, e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	for _, journals := range [][]*evidence.Journal{{f.journal, active}, {active, f.journal}} {
		if p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, journals, active, f.until, proof, &carry, public); !errors.Is(e, ErrEvidenceGap) || p != nil {
			t.Fatal("new active journal reset owner floor", e)
		}
		if p, e := OpenPostingsWithRetiredOriginals(parent, f.owner, nil, journals, active, f.until, map[uint64]BodyReclamation{1700000000: proof}, map[uint64]BodyCarry{1700000000: carry}, public); !errors.Is(e, ErrEvidenceGap) || p != nil {
			t.Fatal("board ignored old journal floor", e)
		}
	}
	p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{active, f.journal}, active, f.until+domain.Time(24*time.Hour), proof, &carry, public)
	if e != nil {
		t.Fatal(e)
	}
	p.Close()
	if e = active.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = active.RequiredRetirementFloor(); !errors.Is(e, store.ErrIncomplete) {
		t.Fatal("closed owner exposed floor", e)
	}
}

func TestRetiredOriginalRecoveryBodylessAndPartial(t *testing.T) {
	for _, mode := range []string{"both", "proposal", "decision"} {
		t.Run(mode, func(t *testing.T) {
			f, parent, proof, carry := retiredRecoveryFixture(t, mode)
			before := retirementFiles(t, f.path)
			p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.until, proof, &carry, f.key.Public().(ed25519.PublicKey))
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			if !p.Reclaimed() || p.Snapshot(f.until) != nil || !p.expired || p.thread != nil {
				t.Fatal("public body resurrected")
			}
			if len(p.OperationIDs()) != 1 || p.OperationIDs()[0] != f.identity.OperationID || bodyRecordsSHA(p.records()) != proof.RecordsSHA {
				t.Fatal("operation correspondence lost")
			}
			if p.reclaimed.carry == nil {
				t.Fatal("carry not validated before recovery")
			}
			history, e := p.RateHistory()
			if e != nil || len(history) != 1 || !reflect.DeepEqual(history[0].Keys, carry.Rates[0].Keys) {
				t.Fatal("retired quota history lost", history, e)
			}
			if mode != "decision" && (history[0].Schema != "required-retired-v1" || history[0].TokenStatus != "unavailable" || history[0].IP != "" || history[0].Token != nil) {
				t.Fatal("original principal or IP reconstructed", history)
			}
			if mode != "decision" && (p.proposals[f.identity.OperationID].payload.Frame != "" || p.proposals[f.identity.OperationID].payload.Capture != nil) {
				t.Fatal("collected original reconstructed")
			}
			if result := p.Post(context.Background(), nil, nil, f.until); result.Status != store.NotWritten {
				t.Fatal("retired thread accepted posting", result)
			}
			if !sameRetirementFiles(before, retirementFiles(t, f.path)) {
				t.Fatal("recovery wrote original journal")
			}
		})
	}
}

func TestRetiredOriginalRecoveryRejectsMissingAndChangedProof(t *testing.T) {
	f, parent, proof, carry := retiredRecoveryFixture(t, "both")
	public := f.key.Public().(ed25519.PublicKey)
	for _, change := range []string{"carry_missing", "carry_changed", "proof_signature", "proof_records", "proof_records_signed", "sequence_signed", "wrong_owner", "wrong_key", "missing_active"} {
		t.Run(change, func(t *testing.T) {
			v := proof
			c := BodyCarry{Dedups: append([]DedupCarry{}, carry.Dedups...), Rates: append([]RateCarry{}, carry.Rates...)}
			selected := &c
			owner, key := f.owner, uint64(1700000000)
			journals := []*evidence.Journal{f.journal}
			switch change {
			case "carry_missing":
				selected = nil
			case "carry_changed":
				c.Rates = nil
			case "proof_signature":
				v.Signature = "bad"
			case "proof_records":
				v.RecordsSHA[0] ^= 1
			case "proof_records_signed":
				v.RecordsSHA[0] ^= 1
				v = signRetiredRecoveryProof(t, v, f.key)
			case "sequence_signed":
				v.Sequence++
				v = signRetiredRecoveryProof(t, v, f.key)
			case "wrong_owner":
				owner = domain.NewID()
			case "wrong_key":
				key++
			case "missing_active":
				journals = nil
			}
			if p, e := OpenPostingWithRetiredOriginals(parent, owner, key, journals, f.journal, f.until, v, selected, public); e == nil || p != nil {
				t.Fatal("invalid recovery accepted", change, e)
			}
		})
	}
	if _, e := OpenPostingWithReclamation(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.until, &proof, public); e == nil {
		t.Fatal("ordinary recovery skipped required tombstone")
	}
	if _, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.until-1, proof, &carry, public); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("clock rollback silently used collected originals", e)
	}
}

// signRetiredRecoveryProof は外側署名だけでは欠損集合を受理しない試験用の正当署名を作る。
func signRetiredRecoveryProof(t *testing.T, v BodyReclamation, key ed25519.PrivateKey) BodyReclamation {
	t.Helper()
	v.Signature = ""
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	v.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("oimo/body-reclamation/v1\x00"), raw...)))
	if e = v.Verify(key.Public().(ed25519.PublicKey)); e != nil {
		t.Fatal("fixture must have valid outer proof", e)
	}
	return v
}

func TestRetiredOriginalRecoveryRejectsConflictingIdentity(t *testing.T) {
	f, _, _, _ := retiredRecoveryFixture(t, "both")
	retired, e := f.journal.RequiredRetirements()
	if e != nil || len(retired) != 2 {
		t.Fatal(retired, e)
	}
	p := &PostingLog{retired: map[domain.ID]retiredPostingOriginals{}}
	if e = p.addRetiredOriginal(retired[0]); e != nil {
		t.Fatal(e)
	}
	r := retired[1]
	r.Identity.Outcome = "not_accepted"
	if e = p.addRetiredOriginal(r); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("conflicting outcome accepted", e)
	}
	if e = p.addRetiredOriginal(retired[0]); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("duplicate retired original accepted", e)
	}
}

func TestRetiredOriginalRecoveryCarryCompletenessAndOldFormatRefusal(t *testing.T) {
	f, parent, proof, carry := retiredRecoveryFixture(t, "both")
	public := f.key.Public().(ed25519.PublicKey)
	c := BodyCarry{Dedups: carry.Dedups, Rates: []RateCarry{}}
	v := proof
	var e error
	v.DedupSHA, v.RateSHA, e = c.Digest(v.Floor)
	if e != nil {
		t.Fatal(e)
	}
	v = signRetiredRecoveryProof(t, v, f.key)
	if p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.until, v, &c, public); e == nil || p != nil {
		t.Fatal("signed schema2 omitted required rate history", e)
	}
	v.Schema = 1
	v.Signature = ""
	raw, _ := json.Marshal(v)
	v.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, append([]byte("oimo/body-reclamation/v1\x00"), raw...)))
	if err := v.Verify(public); err == nil {
		t.Fatal("old body reclamation accepted")
	}
	if p, err := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.until, v, &c, public); err == nil || p != nil {
		t.Fatal("old format recovered", err)
	}
}

func sameRetirementFiles(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, raw := range a {
		if string(raw) != string(b[name]) {
			return false
		}
	}
	return true
}
