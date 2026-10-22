// 稼働中の原本回収後もraw frame/captureを残さず、物理回収/carry不足を拒否する。
package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"reflect"
	"testing"
)

func originalReclamationFixture(t *testing.T) (retirementFixture, *PostingLog, BodyReclamation, BodyCarry) {
	t.Helper()
	f := newRetirementFixture(t)
	parent := filepath.Join(filepath.Dir(f.path), "threads")
	p, e := OpenPosting(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.identity.Committed)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = p.Close() })
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
	return f, p, proof, carry
}

func TestRequiredOriginalReclamationRequiresPhysicalRemovalAndIndependentCarry(t *testing.T) {
	f, p, proof, carry := originalReclamationFixture(t)
	public := f.key.Public().(ed25519.PublicKey)
	before := retirementFiles(t, f.path)
	if e := p.CheckRequiredOriginalReclamation(t.Context(), f.until, public); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("missing independent carry allowed", e)
	}
	if e := p.UseBodyCarry(carry); e != nil {
		t.Fatal(e)
	}
	if e := p.CheckRequiredOriginalReclamation(t.Context(), f.until, public); e == nil {
		t.Fatal("proof alone allowed original reclamation")
	}
	if e := store.RemoveReclaimedBody(t.Context(), filepath.Join(p.parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	if e := p.CheckRequiredOriginalReclamation(t.Context(), f.until-1, public); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("clock rollback allowed", e)
	}
	if e := p.CheckRequiredOriginalReclamation(t.Context(), f.until, public); e != nil {
		t.Fatal(e)
	}
	original, err := p.proposals[f.identity.OperationID].decodeFrame()
	if err != nil || len(original) == 0 {
		t.Fatal("保存済み原本が読めない", err)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
		t.Fatal("preflight changed original storage")
	}
}

func TestReloadRetiredOriginalsDropsLiveMemoryBodiesAndKeepsRateHistory(t *testing.T) {
	f, p, proof, carry := originalReclamationFixture(t)
	if e := p.UseBodyCarry(carry); e != nil {
		t.Fatal(e)
	}
	if e := store.RemoveReclaimedBody(t.Context(), filepath.Join(p.parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), []*evidence.Journal{f.journal}, f.journal, []evidence.RequiredPostingIdentity{f.identity}, f.until, public, noOriginalPairHold); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	checkLiveRetiredOwner(t, p, f.identity.OperationID, carry)
	if e := p.ReloadRetiredOriginals(t.Context(), []*evidence.Journal{f.journal}, f.until, public); e != nil {
		t.Fatal("repeat refresh failed", e)
	}
}

func checkLiveRetiredOwner(t *testing.T, p *PostingLog, id domain.ID, carry BodyCarry) {
	t.Helper()
	entry := p.proposals[id]
	if entry.payload.Frame != "" || len(entry.payload.Capture) != 0 || len(entry.event.Payload) != 0 || p.thread != nil || !p.expired {
		t.Fatal("live owner kept original bodies")
	}
	history, e := p.RateHistory()
	if e != nil || len(history) != 1 || history[0].Schema != RetiredRateSchema || !reflect.DeepEqual(history[0].Keys, carry.Rates[0].Keys) {
		t.Fatal("quota history lost", history, e)
	}
}

func noOriginalPairHold(evidence.RequiredPostingIdentity, domain.Time) (bool, error) {
	return false, nil
}

func TestRequiredOriginalBatchProtectsPairAndRejectsChangedCandidate(t *testing.T) {
	f, p, proof, carry := originalReclamationFixture(t)
	if e := p.UseBodyCarry(carry); e != nil {
		t.Fatal(e)
	}
	if e := store.RemoveReclaimedBody(t.Context(), filepath.Join(p.parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	before := retirementFiles(t, f.path)
	journals := []*evidence.Journal{f.journal}
	candidates := []evidence.RequiredPostingIdentity{f.identity}
	held := func(evidence.RequiredPostingIdentity, domain.Time) (bool, error) { return true, nil }
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), journals, f.journal, candidates, f.until, public, held); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	candidates[0].DecisionSHA[0] ^= 1
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), journals, f.journal, candidates, f.until, public, noOriginalPairHold); !errors.Is(e, ErrEvidenceGap) || n != 0 || p.stopped {
		t.Fatal("changed candidate reached mutation", n, e)
	}
	if !reflect.DeepEqual(before, retirementFiles(t, f.path)) {
		t.Fatal("rejected batch changed files")
	}
}

func TestRequiredOriginalBatchCompletesPartiallyRetiredPair(t *testing.T) {
	for _, side := range []string{"proposal", "decision"} {
		t.Run(side, func(t *testing.T) {
			f, parent, proof, carry := retiredRecoveryFixture(t, side)
			public := f.key.Public().(ed25519.PublicKey)
			journals := []*evidence.Journal{f.journal}
			p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, journals, f.journal, f.until, proof, &carry, public)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			if n, e := p.PruneRequiredOriginalBatch(t.Context(), journals, f.journal, []evidence.RequiredPostingIdentity{f.identity}, f.until, public, noOriginalPairHold); e != nil || n != 1 {
				t.Fatal(n, e)
			}
			if p.proposals[f.identity.OperationID].payload.Frame != "" || len(p.proposals[f.identity.OperationID].payload.Capture) != 0 {
				t.Fatal("partial batch kept raw body")
			}
		})
	}
}

func TestReloadRetiredOriginalsStopsOwnerOnIncompleteRecovery(t *testing.T) {
	f, p, proof, carry := originalReclamationFixture(t)
	if e := p.UseBodyCarry(carry); e != nil {
		t.Fatal(e)
	}
	if e := store.RemoveReclaimedBody(t.Context(), filepath.Join(p.parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	if n, e := f.journal.PruneRequired(f.until, f.selectIdentity, noRetirementHold, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	if e := p.ReloadRetiredOriginals(t.Context(), nil, f.until, f.key.Public().(ed25519.PublicKey)); e == nil || !p.stopped {
		t.Fatal("failed owner resumed", e)
	}
}
