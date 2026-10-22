// 元payloadと署名文脈の改変・別案件への取り違えを検査する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"oimobbs/internal/domain"
	"testing"
)

func TestEventIntegrity(t *testing.T) {
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	src := Source{domain.NewID(), 20260928, 1}
	payload := []byte(fmt.Sprintf(`{"source_owner_id":"%s","source_subkey":"20260928","source_control_seq":"1","content":"private"}`, src.Owner))
	event, e := Seal(src, domain.NewID(), "evidence_proposal", payload, domain.Hash{}, 1, key)
	if e != nil {
		t.Fatal(e)
	}
	got, e := Verify(src, event, domain.Hash{}, 1, pub)
	if e != nil || !bytes.Equal(payload, got) {
		t.Fatal(e)
	}
	for _, change := range []func(*Event){func(e *Event) { e.Payload += "A" }, func(e *Event) { e.EventSHA[0] ^= 1 }, func(e *Event) { e.Signature = "" }, func(e *Event) { e.PreviousSHA[0] = 1 }, func(e *Event) { e.Kind = "attempt" }, func(e *Event) { e.RecordID = domain.NewID() }} {
		bad := event
		change(&bad)
		if _, e = Verify(src, bad, domain.Hash{}, 1, pub); e == nil {
			t.Fatal("tampered accepted")
		}
	}
	src.Seq++
	if _, e = Verify(src, event, domain.Hash{}, 1, pub); e == nil {
		t.Fatal("wrong sequence")
	}
}
