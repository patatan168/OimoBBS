// 板全体の分類・回収済みキーの予約高水位・欠損時の全結果拒否を実fileで検査する。
package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"testing"
)

func TestRetiredBoardRecoveryAndWatermark(t *testing.T) {
	f, parent, proof, carry := retiredRecoveryFixture(t, "both")
	journals := []*evidence.Journal{f.journal}
	if e := CheckPostingKeys(journals, 1699999999); e == nil {
		t.Fatal("retired key exceeded watermark")
	}
	if e := CheckPostingKeys(journals, 1700000000); e != nil {
		t.Fatal(e)
	}
	proofs := map[uint64]BodyReclamation{1700000000: proof}
	carries := map[uint64]BodyCarry{1700000000: carry}
	// 実ディレクトリ一覧にない回収済みキーと、未使用の予約キーを同じ分類から復旧する。
	opened, e := OpenPostingsWithRetiredOriginals(parent, f.owner, []uint64{1700000001}, journals, f.journal, f.until, proofs, carries, f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range opened {
		defer p.Close()
	}
	if len(opened) != 2 || !opened[1700000000].Reclaimed() || opened[1700000001].Reclaimed() {
		t.Fatal("key union differs")
	}
	if got := opened[1700000000].OperationIDs(); len(got) != 1 || got[0] != f.identity.OperationID {
		t.Fatal("retired operation ID lost")
	}
	if history, e := opened[1700000000].RateHistory(); e != nil || len(history) != 1 || history[0].IP != "" {
		t.Fatal(history, e)
	}
}

func TestRetiredBoardMixesCollectedAndFullOriginals(t *testing.T) {
	f := newRetirementFixture(t)
	parent := filepath.Join(filepath.Dir(f.path), "threads")
	_, raw, committed := postingFixture(t)
	frame, _, e := store.ReadFrame(bytes.NewReader(raw))
	if e != nil {
		t.Fatal(e)
	}
	frame.Records[0].ID = domain.NewID()
	raw, e = store.EncodeFrame(frame)
	if e != nil {
		t.Fatal(e)
	}
	second, e := OpenPosting(parent, f.owner, 1700000001, []*evidence.Journal{f.journal}, f.journal, committed)
	if e != nil {
		t.Fatal(e)
	}
	if result := second.Post(context.Background(), raw, []byte(`{"fixture":true}`), committed); result.Status != store.Durable {
		t.Fatal(result)
	}
	if e = second.Close(); e != nil {
		t.Fatal(e)
	}
	first, e := OpenPosting(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, committed)
	if e != nil {
		t.Fatal(e)
	}
	proof, e := first.PrepareBodyReclamation(context.Background(), domain.NewID(), "expire", f.until, f.key)
	if e != nil {
		t.Fatal(e)
	}
	carry, e := first.ExportBodyCarry(proof.Floor, proof.CarryAt())
	if e != nil {
		t.Fatal(e)
	}
	if e = first.RetireBody(proof); e != nil {
		t.Fatal(e)
	}
	if e = store.RemoveReclaimedBody(context.Background(), filepath.Join(parent, "1700000000"), proof.Files, nil); e != nil {
		t.Fatal(e)
	}
	if e = first.Close(); e != nil {
		t.Fatal(e)
	}
	selectFirst := func(entry evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
		if entry.Event.RecordID != f.identity.ProposalID && entry.Event.RecordID != f.identity.DecisionID {
			return nil, nil
		}
		return f.selectIdentity(entry)
	}
	if n, e := f.journal.PruneRequired(f.until, selectFirst, noRetirementHold, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	opened, e := OpenPostingsWithRetiredOriginals(parent, f.owner, nil, []*evidence.Journal{f.journal}, f.journal, f.until, map[uint64]BodyReclamation{1700000000: proof}, map[uint64]BodyCarry{1700000000: carry}, f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range opened {
		defer p.Close()
	}
	if len(opened) != 2 || !opened[1700000000].Reclaimed() || opened[1700000001].Reclaimed() || opened[1700000001].thread == nil {
		t.Fatal("mixed recovery chose wrong paths")
	}
	if ids := opened[1700000001].OperationIDs(); len(ids) != 1 || ids[0] != frame.Records[0].ID {
		t.Fatal("full original operation changed", ids)
	}
}

func TestRetiredBoardRejectsMissingAndForeignInputs(t *testing.T) {
	f, parent, proof, carry := retiredRecoveryFixture(t, "both")
	public := f.key.Public().(ed25519.PublicKey)
	for _, missing := range []string{"proof", "carry", "active", "duplicate_journal", "clock", "orphan_carry", "zero_key"} {
		t.Run(missing, func(t *testing.T) {
			proofs := map[uint64]BodyReclamation{1700000000: proof}
			carries := map[uint64]BodyCarry{1700000000: carry}
			journals := []*evidence.Journal{f.journal}
			keys := []uint64{1} // 先に開いた空writerも失敗時に返さない。
			now := f.until
			switch missing {
			case "proof":
				proofs = nil
			case "carry":
				carries = nil
			case "active":
				journals = nil
			case "duplicate_journal":
				journals = append(journals, f.journal)
			case "clock":
				now--
			case "orphan_carry":
				carries[1700000001] = carry
			case "zero_key":
				keys = []uint64{0}
			}
			if result, e := OpenPostingsWithRetiredOriginals(parent, f.owner, keys, journals, f.journal, now, proofs, carries, public); e == nil || result != nil {
				t.Fatal("partial/invalid board accepted", result, e)
			}
		})
	}
}

func TestRetiredBoardOperationAndEventCollision(t *testing.T) {
	f, _, _, _ := retiredRecoveryFixture(t, "both")
	retired, e := f.journal.RequiredRetirements()
	if e != nil {
		t.Fatal(e)
	}
	g, e := groupPostingEvidence(f.owner, []*evidence.Journal{f.journal}, f.journal)
	if e != nil {
		t.Fatal(e)
	}
	if e = g.bindOperation(1700000001, f.identity.OperationID); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("operation moved to another key", e)
	}
	if e = g.addRetirement(retired[0]); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("retired source ID reused", e)
	}
	if e = g.bindOperation(0, domain.NewID()); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("zero key accepted", e)
	}
}

func TestRetiredBoardKeepsFullOriginalThreadPath(t *testing.T) {
	f := newRetirementFixture(t)
	if e := CheckPostingKeys([]*evidence.Journal{f.journal}, 1700000000); e != nil {
		t.Fatal(e)
	}
	// 原本回収なしは従来の完全frame照合で復旧する。
	parent := filepath.Join(filepath.Dir(f.path), "threads")
	opened, e := OpenPostingsWithRetiredOriginals(parent, f.owner, nil, []*evidence.Journal{f.journal}, f.journal, f.identity.Committed, nil, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer opened[1700000000].Close()
	if opened[1700000000].Snapshot(f.identity.Committed) == nil {
		t.Fatal("live original skipped")
	}
}
