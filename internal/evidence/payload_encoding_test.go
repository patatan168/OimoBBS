// base64照合の境界と、journalの完全検証が通常Verifyと一致することを検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func FuzzPayloadEncodingEquivalence(f *testing.F) {
	for _, n := range []int{0, 1, 2, 3, 767, 768, 769, 1536, 1537} {
		raw := bytes.Repeat([]byte{0xff}, n)
		encoded := base64.StdEncoding.EncodeToString(raw)
		f.Add(raw, encoded)
		f.Add(raw, encoded+"\n")
	}
	f.Fuzz(func(t *testing.T, raw []byte, encoded string) {
		if got, want := matchesPayloadEncoding(raw, encoded), base64.StdEncoding.EncodeToString(raw) == encoded; got != want {
			t.Fatal("encoding mismatch", len(raw), len(encoded))
		}
	})
}

func TestJournalValueVerificationEquivalence(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	source := Source{domain.ID{1}, 20261017, 1}
	payload, err := json.Marshal(testPayload{source.Owner, domain.U64(source.Subkey), domain.U64(source.Seq), strings.Repeat("検証本文", 400)})
	if err != nil {
		t.Fatal(err)
	}
	event, err := Seal(source, domain.ID{2}, "attempt", payload, domain.Hash{}, 10, key)
	if err != nil {
		t.Fatal(err)
	}
	j := &Journal{owner: source.Owner, day: source.Subkey, keyID: 10, key: key, validate: testValidator}
	for _, mode := range []string{"valid", "payload", "newline", "signature", "hash", "key", "schema", "owner", "day", "zero_seq", "unknown_field", "duplicate_field"} {
		t.Run(mode, func(t *testing.T) {
			changed := event
			switch mode {
			case "payload":
				changed.Payload = base64.StdEncoding.EncodeToString([]byte(`{}`))
			case "newline":
				changed.Payload += "\n"
			case "signature":
				changed.Signature = strings.Repeat("A", len(event.Signature))
			case "hash":
				changed.EventSHA[0] ^= 1
			case "key":
				changed.SigningKeyID++
			case "schema":
				changed.Schema = "unknown"
			default:
				modified := bytes.Clone(payload)
				switch mode {
				case "owner":
					modified = bytes.Replace(modified, []byte(source.Owner.String()), []byte(domain.ID{3}.String()), 1)
				case "day":
					modified = bytes.Replace(modified, []byte("20261017"), []byte("20261018"), 1)
				case "zero_seq":
					modified = bytes.Replace(modified, []byte(`"source_control_seq":"1"`), []byte(`"source_control_seq":"0"`), 1)
				case "unknown_field":
					modified = append([]byte(`{"extra":true,`), modified[1:]...)
				case "duplicate_field":
					modified = append([]byte(`{"content":"other",`), modified[1:]...)
				}
				if mode != "valid" {
					changed.Payload = base64.StdEncoding.EncodeToString(modified)
				}
			}
			value, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			got := j.validateValue("attempt", changed.RecordID.String(), nil, value)
			decoded, want := Verify(source, changed, changed.PreviousSHA, 10, key.Public().(ed25519.PublicKey))
			if want == nil {
				want = testValidator(changed.Kind, decoded)
			}
			if (got == nil) != (want == nil) || (got == nil) != (mode == "valid") {
				t.Fatal("verification differs", got, want)
			}
		})
	}
}

// 有効な署名でも所有者/日付/完全型が異なる行は採用しない。
func TestJournalRejectsSignedForeignSourceAndInvalidSchema(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	owner := domain.ID{1}
	for _, tc := range []struct {
		name   string
		source Source
		extra  bool
	}{
		{"owner", Source{domain.ID{3}, 20261017, 1}, false},
		{"day", Source{owner, 20261018, 1}, false},
		{"schema", Source{owner, 20261017, 1}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := json.Marshal(testPayload{tc.source.Owner, domain.U64(tc.source.Subkey), domain.U64(tc.source.Seq), "private"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.extra {
				payload = append([]byte(`{"extra":true,`), payload[1:]...)
			}
			event, err := Seal(tc.source, domain.ID{2}, "attempt", payload, domain.Hash{}, 10, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(tc.source, event, domain.Hash{}, 10, key.Public().(ed25519.PublicKey)); err != nil {
				t.Fatal("fixture signature invalid", err)
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			j := &Journal{owner: owner, day: 20261017, keyID: 10, key: key, validate: testValidator}
			if err := j.validateValue("attempt", event.RecordID.String(), nil, raw); err == nil {
				t.Fatal("accepted signed foreign source or invalid schema")
			}
		})
	}
}
