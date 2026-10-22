// 容量回収の原本は元期限を保ち、保全と署名付き復旧を維持する。
package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"path/filepath"
	"testing"
)

func TestStoragePressureOriginalRetirement(t *testing.T) {
	f := newRetirementFixture(t)
	now := f.identity.Committed + domain.Time(7*24*60*60*1e9)
	held := func(domain.ID, domain.Time) (bool, error) { return true, nil }
	if n, e := f.journal.PruneRequiredPressure(now, f.selectIdentity, held, nil); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if n, e := f.journal.PruneRequiredPressure(now, f.selectIdentity, noRetirementHold, nil); e != nil || n != 2 {
		t.Fatal(n, e)
	}
	rows, e := f.journal.RequiredRetirements()
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	for _, row := range rows {
		if !row.Pressure || row.Until != f.until || row.Identity.Outcome != "accepted" {
			t.Fatal(row)
		}
	}
	assertRetiredPayloadAbsent(t, f)
	if e = f.journal.Close(); e != nil {
		t.Fatal(e)
	}
	j, e := evidence.OpenJournal(f.path, f.owner, 20231114, 10, f.key, PostingValidator(fixtureCapture))
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	rows, e = j.RequiredRetirements()
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
}

// 早期原本回収の許可は公開回収署名に束縛し、通常満了の検査には広げない。
func TestStoragePressureSignedBodyAndRateRecovery(t *testing.T) {
	for _, side := range []string{"both", "proposal", "decision"} {
		t.Run(side, func(t *testing.T) {
			f := newRetirementFixture(t)
			now := f.identity.Committed + domain.Time(8*24*60*60*1e9)
			parent := filepath.Join(filepath.Dir(f.path), "threads")
			p, e := OpenPosting(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, now)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Close()
			proof, e := p.PrepareBodyReclamation(t.Context(), domain.NewID(), "pressure", now, f.key)
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
			if e = p.UseBodyCarry(carry); e != nil {
				t.Fatal(e)
			}
			if e = store.RemoveReclaimedBody(t.Context(), filepath.Join(parent, "1700000000"), proof.Files, nil); e != nil {
				t.Fatal(e)
			}
			choose := func(entry evidence.Entry) (*evidence.RequiredPostingIdentity, error) {
				if side == "proposal" && entry.Event.Kind != "evidence_proposal" || side == "decision" && entry.Event.Kind != "evidence_decision" {
					return nil, nil
				}
				return f.selectIdentity(entry)
			}
			n, e := f.journal.PruneRequiredPressure(now, choose, noRetirementHold, nil)
			want := 1
			if side == "both" {
				want = 2
			}
			if e != nil || n != want {
				t.Fatal(n, e)
			}
			public := f.key.Public().(ed25519.PublicKey)
			restored, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, now, proof, &carry, public)
			if e != nil {
				t.Fatal(e)
			}
			defer restored.Close()
			rows, e := restored.RateHistory()
			if e != nil || len(rows) != 1 {
				t.Fatal(rows, e)
			}
			if side != "decision" {
				if e = ValidateRetiredRateRecord(f.owner, 1700000000, rows[0], now); e != nil {
					t.Fatal(e)
				}
			}
			invalid := proof
			invalid.Kind = "expire"
			invalid.Signature = ""
			raw, _ := json.Marshal(invalid)
			invalid.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(f.key, append([]byte("oimo/body-reclamation/v1\x00"), raw...)))
			if _, e = OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, now, invalid, &carry, public); e == nil {
				t.Fatal("pressure original restored using normal expiry")
			}
		})
	}
}
