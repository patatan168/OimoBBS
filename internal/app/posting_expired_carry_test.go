// 満了carryの所有者接続と、必須原本回収後の復旧・時計逆行拒否を検査する。
package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"reflect"
	"testing"
)

func TestExpiredCarryReopensAfterRequiredOriginalReclamation(t *testing.T) {
	f, p, proof, original := originalReclamationFixture(t)
	at := f.until + 3600e9
	certificate, e := PrepareBodyCarryRetirement(proof, original, at, f.key)
	if e != nil {
		t.Fatal(e)
	}
	carry := BodyCarry{Dedups: []DedupCarry{}, Rates: []RateCarry{}, Retirement: &certificate}
	public := f.key.Public().(ed25519.PublicKey)
	if e = p.RestoreBodyCarry(carry, at, public); e != nil {
		t.Fatal(e)
	}
	if e = store.RemoveReclaimedBody(t.Context(), filepath.Join(p.parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	if n, e := p.PruneRequiredOriginalBatch(t.Context(), []*evidence.Journal{f.journal}, f.journal, []evidence.RequiredPostingIdentity{f.identity}, at, public, noOriginalPairHold); e != nil || n != 2 {
		t.Fatal("original reclamation", n, e)
	}
	assertExpiredCarryHistoryEmpty(t, p)
	if e = p.ReloadRetiredOriginals(t.Context(), []*evidence.Journal{f.journal}, at, public); e != nil {
		t.Fatal("reopen", e)
	}
	assertExpiredCarryHistoryEmpty(t, p)
	if _, e = OpenPostingWithRetiredOriginals(p.parent, p.owner, p.key, []*evidence.Journal{f.journal}, f.journal, at-1, proof, &carry, public); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("rollback allowed", e)
	}
}

func assertExpiredCarryHistoryEmpty(t *testing.T, p *PostingLog) {
	t.Helper()
	history, e := p.RateHistory()
	if e != nil || len(history) != 0 {
		t.Fatal("expired quota resurrected", history, e)
	}
	for _, r := range p.records() {
		if r.Dedup != nil {
			t.Fatal("expired dedup resurrected")
		}
	}
}

func TestExpiredCarryRejectsRollbackAndNonemptyRowsBeforeChange(t *testing.T) {
	f, p, proof, original := originalReclamationFixture(t)
	at := f.until + 3600e9
	certificate, e := PrepareBodyCarryRetirement(proof, original, at, f.key)
	if e != nil {
		t.Fatal(e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	carry := BodyCarry{Retirement: &certificate}
	if e = p.RestoreBodyCarry(carry, at-1, public); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal(e)
	}
	carry.Rates = original.Rates
	if e = p.RestoreBodyCarry(carry, at, public); e == nil {
		t.Fatal("remaining private rows accepted")
	}
	if p.reclaimed.carry != nil {
		t.Fatal("failed restore changed owner")
	}
}

func TestExpiredCarryOwnerDoesNotBorrowCertificate(t *testing.T) {
	f, p, proof, original := originalReclamationFixture(t)
	certificate, e := PrepareBodyCarryRetirement(proof, original, f.until, f.key)
	if e != nil {
		t.Fatal(e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	carry := BodyCarry{Retirement: &certificate}
	if e = p.RestoreBodyCarry(carry, f.until, public); e != nil {
		t.Fatal(e)
	}
	certificate.At++
	if e = p.reclaimed.carry.Retirement.Verify(proof, f.until, public); e != nil {
		t.Fatal("borrowed certificate changed owned proof", e)
	}
}

func TestExpiredCarryBoardRecoveryWithFullOriginals(t *testing.T) {
	f, p, proof, original := originalReclamationFixture(t)
	at := f.until + 3600e9
	certificate, e := PrepareBodyCarryRetirement(proof, original, at, f.key)
	if e != nil {
		t.Fatal(e)
	}
	if e = store.RemoveReclaimedBody(t.Context(), filepath.Join(p.parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	if e = p.Close(); e != nil {
		t.Fatal(e)
	}
	opened, e := OpenPostingsWithRetiredOriginals(p.parent, f.owner, nil, []*evidence.Journal{f.journal}, f.journal, at, map[uint64]BodyReclamation{p.key: proof}, map[uint64]BodyCarry{p.key: {Retirement: &certificate}}, f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	defer opened[p.key].Close()
	assertExpiredCarryHistoryEmpty(t, opened[p.key])
	if ids := opened[p.key].OperationIDs(); len(ids) != 1 || ids[0] != f.identity.OperationID {
		t.Fatal("fixed operation identity lost")
	}
}

func TestExpiredCarryBoardRollbackPrecedesOtherKeyRepair(t *testing.T) {
	f, p, proof, original := originalReclamationFixture(t)
	at := f.until + 3600e9
	certificate, e := PrepareBodyCarryRetirement(proof, original, at, f.key)
	if e != nil {
		t.Fatal(e)
	}
	makePendingCarrySibling(t, f, p.parent)
	before := len(f.journal.Entries())
	beforeFiles := retirementFiles(t, f.path)
	proofs := map[uint64]BodyReclamation{p.key: proof}
	carries := map[uint64]BodyCarry{p.key: {Retirement: &certificate}}
	if _, e = OpenPostingsWithRetiredOriginals(p.parent, f.owner, nil, []*evidence.Journal{f.journal}, f.journal, at-1, proofs, carries, f.key.Public().(ed25519.PublicKey)); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("rollback allowed", e)
	}
	if len(f.journal.Entries()) != before || !reflect.DeepEqual(beforeFiles, retirementFiles(t, f.path)) {
		t.Fatal("another key repaired before clock check")
	}
}

func makePendingCarrySibling(t *testing.T, f retirementFixture, parent string) {
	t.Helper()
	_, frame, at := postingFixture(t)
	data, _, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	data.Records[0].ID = domain.NewID()
	var op domain.Operation
	if e = json.Unmarshal(data.Records[0].JSON, &op); e != nil {
		t.Fatal(e)
	}
	op.Dedup.Request[0] ^= 1
	data.Records[0].JSON, _ = json.Marshal(op)
	frame, e = store.EncodeFrame(data)
	if e != nil {
		t.Fatal(e)
	}
	other, e := OpenPosting(parent, f.owner, 1699999999, []*evidence.Journal{f.journal}, f.journal, at)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	stoppedAtThread := false
	before := len(f.journal.Entries())
	other.checkpoint = func(stage string) error {
		if stage == "thread" {
			stoppedAtThread = true
			return errors.New("test stop")
		}
		return nil
	}
	if result := other.Post(t.Context(), frame, []byte(`{"fixture":true}`), at); result.Status != store.Unknown || !stoppedAtThread || len(f.journal.Entries()) != before+1 {
		t.Fatal("pending sibling not prepared")
	}
}
