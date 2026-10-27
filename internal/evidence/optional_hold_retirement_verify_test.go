// 公開鍵だけの候補検査が元署名・サイト・前後索引と解除metadataを束縛することを検査する。
package evidence

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func TestVerifyOptionalHoldRetirementCandidateUsesPublicKeyOnly(t *testing.T) {
	s, candidate, b, _, at := prepareOptionalRetirementFixture(t)
	public := s.key.Public().(ed25519.PublicKey)
	desc, err := VerifyOptionalHoldRetirementCandidate(s.site, public, candidate)
	if err != nil {
		t.Fatal(err)
	}
	released, _, err := s.OptionalHoldReceipt(b.Case)
	if err != nil {
		t.Fatal(err)
	}
	if desc.Case != b.Case || desc.Fingerprint != (domain.Hash{1}) || desc.Registration != (domain.Hash{2}) || desc.Release != released.SHA || desc.At != domain.Time(at.UnixNano()) {
		t.Fatal("public verification lost source binding")
	}
	assertOptionalRetirementPublicKeyRejects(t, s.site, public, candidate)
}

func assertOptionalRetirementPublicKeyRejects(t *testing.T, site domain.ID, public ed25519.PublicKey, candidate OptionalHoldRetirementCandidate) {
	t.Helper()
	for _, key := range []ed25519.PublicKey{nil, public[:len(public)-1], make(ed25519.PublicKey, ed25519.PublicKeySize)} {
		if _, err := VerifyOptionalHoldRetirementCandidate(site, key, candidate); !errors.Is(err, store.ErrCorrupt) {
			t.Fatal("invalid public key accepted", err)
		}
	}
	if _, err := VerifyOptionalHoldRetirementCandidate(domain.NewID(), public, candidate); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("other site accepted", err)
	}
	changed := candidate
	changed.Previous.EventSHA[0] ^= 1
	if _, err := VerifyOptionalHoldRetirementCandidate(site, public, changed); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("previous signature binding lost", err)
	}
	changed = candidate
	changed.Next.PreviousSHA[0] ^= 1
	if _, err := VerifyOptionalHoldRetirementCandidate(site, public, changed); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("index chain binding lost", err)
	}
	changed = candidate
	changed.Previous = changed.Next
	if _, err := VerifyOptionalHoldRetirementCandidate(site, public, changed); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("identical indices treated as removal", err)
	}
}
