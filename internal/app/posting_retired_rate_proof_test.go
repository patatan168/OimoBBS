// 検証済み回収履歴の内部証明がSchema偽装・使い回し・原文混在を拒否することを検査する。
package app

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"testing"
)

func TestRetiredRateProofBindingAndClock(t *testing.T) {
	f, parent, proof, carry := retiredRecoveryFixture(t, "both")
	p, e := OpenPostingWithRetiredOriginals(parent, f.owner, 1700000000, []*evidence.Journal{f.journal}, f.journal, f.until, proof, &carry, f.key.Public().(ed25519.PublicKey))
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	rows, e := p.RateHistory()
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	base := rows[0]
	if e = ValidateRetiredRateRecord(f.owner, 1700000000, base, f.until); e != nil {
		t.Fatal(e)
	}
	if e = ValidateRetiredRateRecord(f.owner, 1700000000, base, f.until-1); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal(e)
	}
	for _, change := range []string{"missing", "zero", "owner", "key", "operation", "number", "time", "create", "keys", "ip", "token", "overrides", "schema", "status"} {
		t.Run(change, func(t *testing.T) {
			v := base
			owner, key := f.owner, uint64(1700000000)
			switch change {
			case "missing":
				v.Retirement = nil
			case "zero":
				v.Retirement = &RateRetirementProof{}
			case "owner":
				owner = domain.NewID()
			case "key":
				key++
			case "operation":
				v.ID = domain.NewID()
			case "number":
				v.PostNumber++
			case "time":
				v.At++
			case "create":
				v.Create = !v.Create
			case "keys":
				v.Keys = append([]domain.RateKey{{Rule: domain.NewID()}}, v.Keys...)
			case "ip":
				v.IP = "192.0.2.1"
			case "token":
				v.Token = &postcapture.TokenEvidence{}
			case "overrides":
				v.Overrides = []domain.ID{domain.NewID()}
			case "schema":
				v.Schema = postcapture.Schema
			case "status":
				v.TokenStatus = "valid"
			}
			if e := ValidateRetiredRateRecord(owner, key, v, f.until); !errors.Is(e, ErrEvidenceGap) {
				t.Fatal("retired proof mismatch accepted", e)
			}
		})
	}
	raw, e := json.Marshal(base)
	if e != nil {
		t.Fatal(e)
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	if _, found := fields["Retirement"]; found {
		t.Fatal("internal proof escaped serialization")
	}
}
