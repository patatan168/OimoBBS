// 元期限境界、署名・集合改変、回収後の時計逆行拒否を検査する。
package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"testing"
)

func carryRetirementFixture(t *testing.T) (retirementFixture, BodyReclamation, BodyCarry, domain.Time) {
	t.Helper()
	f, _, proof, carry := originalReclamationFixture(t)
	proof.Kind, proof.At, proof.After.State = "hide", f.identity.Committed+1, "hidden"
	signCarryFixtureProof(t, &proof, f.key)
	deadline, e := carry.latestExpiry(proof.Floor)
	if e != nil || deadline <= proof.At {
		t.Fatal("unexpired fixture", e)
	}
	return f, proof, carry, deadline
}

func signCarryFixtureProof(t *testing.T, proof *BodyReclamation, key ed25519.PrivateKey) {
	t.Helper()
	proof.Signature = ""
	raw, e := json.Marshal(proof)
	if e != nil {
		t.Fatal(e)
	}
	proof.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("oimo/body-reclamation/v1\x00"), raw...)))
}

func TestBodyCarryRetirementDeadlineAndClock(t *testing.T) {
	f, proof, carry, deadline := carryRetirementFixture(t)
	if _, e := PrepareBodyCarryRetirement(proof, carry, deadline-1, f.key); !errors.Is(e, ErrBodyCarryNotExpired) {
		t.Fatal("premature retirement", e)
	}
	v, e := PrepareBodyCarryRetirement(proof, carry, deadline, f.key)
	if e != nil {
		t.Fatal(e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	if v.Verify(proof, deadline, public) != nil || v.LatestExpiry != deadline || v.At != deadline || v.Dedups != uint32(len(carry.Dedups)) || v.Rates != uint32(len(carry.Rates)) {
		t.Fatal("deadline/signature changed")
	}
	if e = v.Verify(proof, deadline-1, public); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("rollback accepted", e)
	}
	if e = v.Verify(proof, deadline+1, public); e != nil {
		t.Fatal(e)
	}
	assertCarryRetirementPrivateAbsent(t, v)
}

func assertCarryRetirementPrivateAbsent(t *testing.T, v BodyCarryRetirement) {
	t.Helper()
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{"entry_base64", "subject_hmac", "rate_keys", "source_ip", "body"} {
		if bytes.Contains(raw, []byte(`"`+field+`"`)) {
			t.Fatal("private carry in receipt", field)
		}
	}
}

func TestBodyCarryRetirementRejectsChangedSetAndProof(t *testing.T) {
	f, proof, carry, deadline := carryRetirementFixture(t)
	if _, e := PrepareBodyCarryRetirement(proof, BodyCarry{}, deadline, f.key); !errors.Is(e, ErrEvidenceGap) {
		t.Fatal("missing set accepted", e)
	}
	v, e := PrepareBodyCarryRetirement(proof, carry, deadline, f.key)
	if e != nil {
		t.Fatal(e)
	}
	public := f.key.Public().(ed25519.PublicKey)
	for _, change := range []func(*BodyCarryRetirement){func(v *BodyCarryRetirement) { v.At++ }, func(v *BodyCarryRetirement) { v.LatestExpiry-- }, func(v *BodyCarryRetirement) { v.Dedups++ }, func(v *BodyCarryRetirement) { v.Proof[0] ^= 1 }} {
		copy := v
		change(&copy)
		if e = copy.Verify(proof, deadline+1, public); e == nil {
			t.Fatal("changed receipt accepted")
		}
	}
	proof.Key++
	signCarryFixtureProof(t, &proof, f.key)
	if e = v.Verify(proof, deadline, public); e == nil {
		t.Fatal("other body proof accepted")
	}
}

func TestBodyCarryRetirementRejectsUntrustedKey(t *testing.T) {
	f, proof, carry, deadline := carryRetirementFixture(t)
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	if _, e := PrepareBodyCarryRetirement(proof, carry, deadline, other); e == nil {
		t.Fatal("other signing key accepted")
	}
	v, e := PrepareBodyCarryRetirement(proof, carry, deadline, f.key)
	if e != nil {
		t.Fatal(e)
	}
	if e = v.Verify(proof, deadline, other.Public().(ed25519.PublicKey)); e == nil {
		t.Fatal("other trusted key accepted")
	}
}

func TestBodyCarryExpiryIncludesRateDeadline(t *testing.T) {
	_, proof, carry, _ := carryRetirementFixture(t)
	carry.Dedups = nil
	latest, e := carry.latestExpiry(proof.Floor)
	if e != nil || latest != carry.Rates[0].At+3660e9 {
		t.Fatal("rate expiry omitted", latest, e)
	}
}
