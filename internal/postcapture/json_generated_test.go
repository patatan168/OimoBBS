// 投稿保存DTOの省略・nullable・escapeを含め、生成JSONを標準実装と照合する。
package postcapture

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/postinput"
	"testing"
)

func captureJSONFixture(t testing.TB) Capture {
	raw, _ := metadataFixture(t)
	var c Capture
	if e := json.Unmarshal(raw, &c); e != nil {
		t.Fatal(e)
	}
	return c
}
func checkCaptureJSON(t testing.TB, c Capture) {
	t.Helper()
	want, we := json.Marshal(c)
	got, ge := MarshalCapture(c)
	if (we == nil) != (ge == nil) || we == nil && !bytes.Equal(want, got) {
		t.Fatalf("capture mismatch %v %v\n%s\n%s", we, ge, want, got)
	}
}
func TestGeneratedCaptureJSON(t *testing.T) {
	c := captureJSONFixture(t)
	checkCaptureJSON(t, c)
	c.Input.CapOnly = true
	c.Input.Controls = &postinput.Controls{ID: "on", Slip: "<>&日本語", Thread: true}
	h := domain.Hash{9}
	c.Input.RequestID = &h
	c.Token = &TokenEvidence{h, domain.RateKey{Rule: domain.ID{1}, KeyID: 7, Subject: h, Cost: 1}}
	c.Cap = &CapEvidence{domain.ID{2}, 1, "資格<&>", 9}
	c.Overrides = []domain.ID{{3}, {4}}
	checkCaptureJSON(t, c)
	c.Overrides = nil
	checkCaptureJSON(t, c)
	c.Overrides = []domain.ID{{}}
	checkCaptureJSON(t, c)
}
func FuzzGeneratedCaptureJSON(f *testing.F) {
	base := captureJSONFixture(f)
	f.Add("日本語<&>\n", uint64(1), false)
	f.Fuzz(func(t *testing.T, s string, n uint64, on bool) {
		c := base
		c.Input.Name = s
		c.Input.Body = s
		c.Input.CapOnly = on
		c.Target = domain.U64(n)
		c.Committed = domain.Time(n)
		checkCaptureJSON(t, c)
	})
}
func BenchmarkGeneratedCaptureJSON(b *testing.B) {
	c := captureJSONFixture(b)
	for _, fast := range []bool{false, true} {
		name := "standard"
		if fast {
			name = "direct"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				if fast {
					_, err = MarshalCapture(c)
				} else {
					_, err = json.Marshal(c)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
