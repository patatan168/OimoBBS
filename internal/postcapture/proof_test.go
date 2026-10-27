// 投稿記録の一括構築とmetadata共有が、個別検証と同じ受理境界を保つことを確認する。
package postcapture

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"reflect"
	"testing"
)

func proofRoundtrip(c Capture, frame []byte, proof Proof) ([]byte, error) {
	raw, err := New(c.Observation, c.Input, uint64(c.Target), c.Display, frame)
	if proof.Cap != nil {
		raw, err = NewWithCap(c.Observation, c.Input, uint64(c.Target), c.Display, frame, *proof.Cap)
	}
	if err != nil {
		return nil, err
	}
	if len(proof.Overrides) > 0 {
		raw, err = WithOverrides(raw, proof.Overrides)
		if err != nil {
			return nil, err
		}
	}
	return WithAnonymous(raw, frame, uint64(c.Target), proof.TokenStatus, proof.Token)
}

func TestProofConstructionEquivalence(t *testing.T) {
	raw, frame := preparedFixture(t)
	c, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"not_checked", "absent", "invalid", "valid", "", "\xff"} {
		for _, ids := range [][]domain.ID{nil, {}, {{4}}, {{4}, {4}}, {{5}, {4}}, {{}}} {
			for _, token := range []*TokenEvidence{nil, {}, {Subject: domain.Hash{1}, Rate: domain.RateKey{Rule: domain.ID{4}, Subject: domain.Hash{1}, KeyID: 7, Cost: 1}}} {
				proof := Proof{TokenStatus: status, Overrides: ids, Token: token}
				want, oldErr := proofRoundtrip(c.Capture, frame, proof)
				got, err := NewWithProof(c.Observation, c.Input, uint64(c.Target), c.Display, frame, proof)
				if (oldErr == nil) != (err == nil) || err == nil && !bytes.Equal(got, want) {
					t.Fatalf("status=%q ids=%v token=%v: old=%v new=%v", status, ids, token, oldErr, err)
				}
			}
		}
	}
}

func checkFrameMetadata(t testing.TB, raw, frame []byte, target uint64) {
	t.Helper()
	c, err := decode(raw)
	if err == nil {
		f, op, e := readFrame(frame)
		err = e
		if err == nil {
			err = validateFrame(c, f, op, frame, target)
		}
	}
	got, actual := ValidateFrameAndMetadata(raw, frame, target)
	if (err == nil) != (actual == nil) || actual != nil && got != nil {
		t.Fatalf("metadata: old=%v new=%v", err, actual)
	}
	if err == nil && !reflect.DeepEqual(got, &c.Capture) {
		t.Fatal("metadata changed")
	}
}

func TestFrameMetadataValidation(t *testing.T) {
	raw, frame := preparedFixture(t)
	for _, body := range [][]byte{raw, []byte(`{`), append([]byte(`{"schema":"form-post-v8",`), raw[1:]...), append([]byte(`{"unknown":true,`), raw[1:]...), bytes.Replace(raw, []byte(`"input":{`), []byte(`"input":null,"ignored":{`), 1)} {
		checkFrameMetadata(t, body, frame, 0)
		checkFrameMetadata(t, body, frame, 1)
		broken := bytes.Clone(frame)
		broken[len(broken)-1] ^= 1
		checkFrameMetadata(t, body, broken, 0)
	}
	c, _ := decode(raw)
	for _, mutate := range []func(*Capture){func(c *Capture) { c.FrameSHA[0] ^= 1 }, func(c *Capture) { c.Input.Body += "changed" }, func(c *Capture) { c.TokenValidation = "valid" }, func(c *Capture) { c.Observation.Resolved.IP = "192.0.2.1" }} {
		next := c.Capture
		mutate(&next)
		body, _ := json.Marshal(next)
		checkFrameMetadata(t, body, frame, 0)
	}
	got, err := ValidateFrameAndMetadata(raw, frame, 0)
	if err != nil {
		t.Fatal(err)
	}
	got.Input.Body = "changed"
	fresh, err := ValidateFrameAndMetadata(raw, frame, 0)
	if err != nil || fresh.Input.Body != c.Input.Body {
		t.Fatal("metadata shared across calls", err)
	}
}

func FuzzFrameMetadata(f *testing.F) {
	raw, frame := preparedFixture(f)
	f.Add(raw, frame)
	f.Fuzz(func(t *testing.T, body, frame []byte) {
		schema, err := schemaOf(body)
		if err != nil || schema != Schema {
			return
		}
		checkFrameMetadata(t, body, frame, 0)
	})
}

func BenchmarkProofConstruction(b *testing.B) {
	raw, frame := preparedFixture(b)
	c, _ := decode(raw)
	proof := Proof{TokenStatus: "absent"}
	for _, mode := range []string{"roundtrip", "combined"} {
		b.Run(mode, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				if mode == "roundtrip" {
					_, err = proofRoundtrip(c.Capture, frame, proof)
				} else {
					_, err = NewWithProof(c.Observation, c.Input, 0, c.Display, frame, proof)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
