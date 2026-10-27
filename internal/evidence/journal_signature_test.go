// 読込内の署名共有が元byte/source照合を省略せず、読込後や別鍵へ残らないことを検査する。
package evidence

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
)

func TestReplaySignatureScopeAndBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	source := Source{domain.ID{1}, 20261017, 1}
	payload, err := json.Marshal(testPayload{source.Owner, domain.U64(source.Subkey), domain.U64(source.Seq), "private"})
	if err != nil {
		t.Fatal(err)
	}
	event, err := Seal(source, domain.ID{2}, "attempt", payload, domain.Hash{}, 10, key)
	if err != nil {
		t.Fatal(err)
	}
	j := &Journal{owner: source.Owner, day: source.Subkey, keyID: 10, key: key, validate: testValidator, replaySignatures: map[verifiedSignature]struct{}{}}
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.validateValue("attempt", event.RecordID.String(), nil, raw); err != nil {
		t.Fatal(err)
	}
	if len(j.replaySignatures) != 1 {
		t.Fatal("signature not shared")
	}
	if _, err := j.verifyReplayPayload(source, event); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"signature", "body", "source", "hash"} {
		t.Run(mode, func(t *testing.T) {
			changed, src := event, source
			switch mode {
			case "signature":
				changed.Signature = "invalid"
			case "body":
				changed.Payload = "e30="
			case "source":
				src.Seq++
			case "hash":
				changed.PayloadSHA[0] ^= 1
			}
			if _, err := j.verifyReplayPayload(src, changed); err == nil {
				t.Fatal("accepted changed record after signature shared")
			}
		})
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	otherKey := ed25519.NewKeyFromSeed(seed)
	other := &Journal{owner: source.Owner, day: source.Subkey, keyID: 10, key: otherKey, validate: testValidator}
	if _, err := other.verifyReplayPayload(source, event); err == nil {
		t.Fatal("signature reused across keys")
	}
	for i := 0; i < maxReplaySignatures-1; i++ {
		j.replaySignatures[verifiedSignature{signature: fmt.Sprint(i)}] = struct{}{}
	}
	before := len(j.replaySignatures)
	next, err := Seal(source, domain.ID{3}, "attempt", payload, domain.Hash{}, 10, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.verifyReplayPayload(source, next); err != nil {
		t.Fatal(err)
	}
	if len(j.replaySignatures) != before {
		t.Fatal("signature capacity exceeded")
	}
}

func TestJournalDiscardsReplaySignatures(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	owner := domain.ID{1}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "20261017")
	j, err := OpenJournal(path, owner, 20261017, 10, key, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	_, saved := j.Append(domain.ID{2}, "attempt", 1, func(s Source) ([]byte, error) {
		return json.Marshal(testPayload{s.Owner, domain.U64(s.Subkey), domain.U64(s.Seq), "private"})
	})
	if saved.Status != store.Durable {
		t.Fatal(saved)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	j, err = OpenJournal(path, owner, 20261017, 10, key, testValidator)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if j.replaySignatures != nil {
		t.Fatal("signature sharing survived OpenJournal")
	}
	if _, err := InspectJournal(path, owner, 20261017, 10, key, testValidator); err != nil {
		t.Fatal(err)
	}
}
