// 型付きの匿名情報結合を従来のJSON往復と比較し、受理条件・出力・frame束縛を検査する。
package postcapture

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"testing"
	"time"
)

func preparedFixture(t testing.TB) ([]byte, []byte) {
	t.Helper()
	raw, _ := metadataFixture(t)
	c, err := decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	rates := make([]domain.RateKey, 3)
	for i := range rates {
		rates[i] = domain.RateKey{Rule: domain.ID{byte(i + 1)}, Subject: domain.Hash{1}, KeyID: 7, Cost: 1}
	}
	context := postinput.BuildContext{AnonymousID: domain.ID{9}, Board: c.Observation.BoardID, SourceIP: c.Observation.Resolved.IP,
		Now: time.Unix(0, int64(c.Committed)), PublicKey: domain.Hash{2}, Bump: 1, Versions: c.Versions, Dedup: c.Dedup, RateKeys: rates,
		Policy: domain.Policy{Version: 1, IDMode: "required", SlipMode: "none", UserPostLimit: 1000, DATUserLimit: 524288, Commands: []string{}},
		Limits: postinput.Limits{Name: 96, Mail: 64, Title: 128, Body: 4096, Lines: 60, Noname: c.Display.Noname, EndMessage: "終了"}}
	frame, err := postinput.Build(nil, c.Input, context)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = New(c.Observation, c.Input, 0, c.Display, frame)
	if err != nil {
		t.Fatal(err)
	}
	return raw, frame
}

func referenceAnonymous(raw, frame []byte, target uint64, status string, token *TokenEvidence) ([]byte, error) {
	c, err := decode(raw)
	if err != nil {
		return nil, err
	}
	c.TokenValidation, c.Token = status, token
	out, err := json.Marshal(c.Capture)
	if err != nil {
		return nil, err
	}
	if err = ValidateFrame(out, frame, target); err != nil {
		return nil, err
	}
	return out, nil
}

func checkAnonymous(t testing.TB, raw, frame []byte, target uint64, status string, token *TokenEvidence) {
	t.Helper()
	before := bytes.Clone(raw)
	want, oldErr := referenceAnonymous(raw, frame, target, status, token)
	got, err := WithAnonymous(raw, frame, target, status, token)
	if (oldErr == nil) != (err == nil) || oldErr == nil && !bytes.Equal(got, want) {
		t.Fatalf("匿名結合の条件または出力が変化: old=%v new=%v", oldErr, err)
	}
	if !bytes.Equal(raw, before) {
		t.Fatal("入力byteが変更された")
	}
}

func TestPreparedAnonymousEquivalence(t *testing.T) {
	raw, frame := preparedFixture(t)
	for _, body := range [][]byte{raw, append(bytes.Clone(raw), '{'), []byte(`{"schema":"form-post-v8"}`), bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":null,"schema":`), 1)} {
		for _, status := range []string{"absent", "invalid", "not_checked", "valid", "", "\xff"} {
			for _, token := range []*TokenEvidence{nil, {}, {Subject: domain.Hash{1}, Rate: domain.RateKey{Rule: domain.ID{4}, Subject: domain.Hash{1}, KeyID: 7, Cost: 1}}} {
				checkAnonymous(t, body, frame, 0, status, token)
				checkAnonymous(t, body, frame, 1, status, token)
			}
		}
	}
	damaged := bytes.Clone(frame)
	damaged[len(damaged)-1] ^= 1
	checkAnonymous(t, raw, damaged, 0, "absent", nil)
	if _, err := WithAnonymous(raw, frame, 0, "absent", nil); err != nil {
		t.Fatal("有効な匿名結合", err)
	}
}

func FuzzPreparedAnonymousEquivalence(f *testing.F) {
	raw, frame := preparedFixture(f)
	f.Add(raw, "absent", false)
	f.Add(raw, "valid", true)
	f.Fuzz(func(t *testing.T, body []byte, status string, withToken bool) {
		var token *TokenEvidence
		if withToken {
			token = &TokenEvidence{Subject: domain.Hash{1}, Rate: domain.RateKey{Rule: domain.ID{4}, Subject: domain.Hash{1}, KeyID: 7, Cost: 1}}
		}
		checkAnonymous(t, body, frame, 0, status, token)
	})
}

func BenchmarkPreparedAnonymous(b *testing.B) {
	raw, frame := preparedFixture(b)
	for _, tc := range []struct {
		name string
		run  func([]byte, []byte, uint64, string, *TokenEvidence) ([]byte, error)
	}{{"roundtrip", referenceAnonymous}, {"prepared", WithAnonymous}} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := tc.run(raw, frame, 0, "absent", nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
