// 合成HTTP観測と投稿入力で、主体鍵検証とmetadata共有の受理条件を比較する。
package postcapture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postinput"
	"reflect"
	"strings"
	"testing"
)

func metadataFixture(t testing.TB) ([]byte, domain.Hash) {
	t.Helper()
	site, board := domain.NewID(), domain.NewID()
	observer, err := evidence.NewHTTPObserver(site, domain.NewID(), "metadata-test")
	if err != nil {
		t.Fatal(err)
	}
	observations := make(chan evidence.HTTPObservation, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture, err := observer.Begin(r, board, "bbs_post", "example.test")
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		if _, err = io.Copy(io.Discard, r.Body); err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		observation, err := capture.Finish()
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		observations <- observation
		w.WriteHeader(204)
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	response, err := server.Client().Post(server.URL+"/test/bbs.cgi", "application/x-www-form-urlencoded", strings.NewReader("synthetic=1"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	observation := <-observations
	key := domain.Hash{1}
	input, err := postinput.Prepare(map[string]string{"subject": "合成試験", "MESSAGE": strings.Repeat("本文と主体の検証", 40)}, true, key)
	if err != nil {
		t.Fatal(err)
	}
	ip := netip.MustParseAddr(observation.Resolved.IP).Unmap()
	family := byte(6)
	if ip.Is4() {
		family = 4
	}
	dedup := input.Dedup(key, board, 0, append([]byte{family}, ip.AsSlice()...), observation.Received)
	dedup.PostNumber = 1
	c := Capture{Schema: Schema, Completeness: "partial", Overrides: []domain.ID{}, Observation: observation, Input: input, Dedup: dedup, Versions: domain.Versions{Site: 1, Board: 1}, Display: Display{Noname: "名無し"}, Committed: observation.Received, BodySHA: sha256.Sum256([]byte(input.Body)), TokenValidation: "not_checked", SubjectSource: "ip", TextCodec: "sjis-compat-v1", Renderer: "dat-v1"}
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKey(raw, key); err != nil {
		t.Fatal(err)
	}
	return raw, key
}

func TestValidateKeyAndMetadata(t *testing.T) {
	raw, key := metadataFixture(t)
	got, err := ValidateKeyAndMetadata(raw, key)
	if err != nil || got == nil {
		t.Fatal(err)
	}
	var want Capture
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatal("metadata changed")
	}
	for _, mode := range []string{"key", "subject", "request", "unknown", "duplicate", "null", "syntax"} {
		t.Run(mode, func(t *testing.T) {
			changed := bytes.Clone(raw)
			chosen := key
			switch mode {
			case "key":
				chosen[0] ^= 1
			case "unknown":
				changed = append([]byte(`{"extra":true,`), raw[1:]...)
			case "duplicate":
				changed = append([]byte(`{"schema":"form-post-v8",`), raw[1:]...)
			case "null":
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &fields); err != nil {
					t.Fatal(err)
				}
				fields["input"] = json.RawMessage("null")
				changed, _ = json.Marshal(fields)
			case "syntax":
				changed = []byte(`{`)
			default:
				value := want
				if mode == "subject" {
					value.Dedup.Subject[0] ^= 1
				} else {
					value.Dedup.Request[0] ^= 1
				}
				changed, _ = json.Marshal(value)
			}
			got, err := ValidateKeyAndMetadata(changed, chosen)
			if err == nil || got != nil {
				t.Fatal("invalid metadata returned", mode, err)
			}
			if ValidateKey(changed, chosen) == nil {
				t.Fatal("legacy accepted invalid capture")
			}
		})
	}
	for _, other := range []string{`{"schema":"http-observation-v4"}`, `{"schema":"custom"}`} {
		got, err := ValidateKeyAndMetadata([]byte(other), key)
		if err != nil || got != nil {
			t.Fatal("other schema changed", err)
		}
	}
	got.Input.Body = "changed"
	fresh, err := ValidateKeyAndMetadata(raw, key)
	if err != nil || fresh.Input.Body != want.Input.Body {
		t.Fatal("metadata retained across calls", err)
	}
}

// BenchmarkCaptureMetadata は同じ完全型・主体鍵検証を個別復号と共有復号で比較する。
func BenchmarkCaptureMetadata(b *testing.B) {
	raw, key := metadataFixture(b)
	b.Run("separate", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := ValidateKey(raw, key); err != nil {
				b.Fatal(err)
			}
			if _, _, _, err := OverrideMetadata(raw); err != nil {
				b.Fatal(err)
			}
			if _, _, _, err := CapMetadata(raw); err != nil {
				b.Fatal(err)
			}
			if _, _, _, err := CapMetadata(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("shared", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ValidateKeyAndMetadata(raw, key); err != nil {
				b.Fatal(err)
			}
		}
	})
}
