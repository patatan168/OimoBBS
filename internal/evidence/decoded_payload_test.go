// 復号済み本文の共有が元base64・署名・sourceの検証を省略しないことを検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"

	"oimobbs/internal/domain"
)

func TestVerifyDecodedPayloadBinding(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	public := key.Public().(ed25519.PublicKey)
	src := Source{domain.ID{1}, 20261016, 1}
	raw := []byte(fmt.Sprintf(`{"source_owner_id":"%s","source_subkey":"20261016","source_control_seq":"1","content":"private"}`, src.Owner))
	event, e := Seal(src, domain.ID{2}, "attempt", raw, domain.Hash{}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	changed := bytes.Replace(raw, []byte("private"), []byte("changed"), 1)
	unsigned := event
	unsigned.Payload = base64.StdEncoding.EncodeToString(changed)
	tests := []struct {
		name    string
		event   Event
		payload []byte
		source  Source
		valid   bool
	}{
		{"same", event, bytes.Clone(raw), src, true},
		{"missing", event, nil, src, false},
		{"other_body", event, changed, src, false},
		{"other_source", event, raw, Source{src.Owner, src.Subkey, 2}, false},
		{"other_envelope_body", unsigned, changed, src, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, e := verifyPayload(tc.source, tc.event, tc.payload, domain.Hash{}, 10, public)
			if (e == nil) != tc.valid || e == nil && !bytes.Equal(got, raw) {
				t.Fatal("decoded payload binding", e)
			}
		})
	}
}
