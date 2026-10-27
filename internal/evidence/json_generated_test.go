// 型定義から生成したJSONの全フィールドとサイズ上界を標準実装へ照合する。
package evidence

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"strings"
	"testing"
)

func checkObservationJSON(t testing.TB, v HTTPObservation) {
	t.Helper()
	want, we := json.Marshal(v)
	got, ge := MarshalHTTPObservation(v)
	if (we == nil) != (ge == nil) || we == nil && !bytes.Equal(want, got) {
		t.Fatalf("observation mismatch: %v %v\n%s\n%s", we, ge, want, got)
	}
	if we == nil {
		for _, limit := range []int{0, 128, 128 << 10} {
			n, e := HTTPObservationJSONBound(v, limit)
			if e != nil || n <= limit && n < len(want) || len(want) > limit && n <= limit {
				t.Fatalf("unsafe observation bound %d / %d, %v", n, len(want), e)
			}
		}
	}
}
func TestGeneratedObservationJSON(t *testing.T) {
	v := decodedObservationFixture(t)
	checkObservationJSON(t, v)
	text := "日本語<&>\\\"\n\u2028"
	rev := domain.U64(^uint64(0))
	tls := uint16(65535)
	v.SNI = &text
	v.ProxyProfileID = &text
	v.BoardAliasUsed = &text
	v.ProxyConfigRevision = &rev
	v.TLSVersion = &tls
	v.TLSCipherSuite = &tls
	v.VerifiedProxyChain = []Endpoint{v.Peer}
	v.OriginEndpoint = &v.Local
	v.ReverseDNS = &ReverseDNSObservation{[]string{text}, text, text, -1, text}
	v.SelectedHeaders = []ObservedHeader{{text, text, []HeaderValue{{text, text}}}}
	v.ReportedHeaders = []ObservedHeader{}
	checkObservationJSON(t, v)
	v.SiteID = domain.ID{}
	checkObservationJSON(t, v)
}
func FuzzGeneratedObservationJSON(f *testing.F) {
	base := decodedObservationFixture(f)
	f.Add("日本語<&>\n", uint64(1))
	f.Fuzz(func(t *testing.T, s string, n uint64) {
		v := base
		v.ServerBuildID = s
		v.Received = domain.Time(n)
		v.SelectedHeaders = []ObservedHeader{{s, s, []HeaderValue{{s, s}}}}
		checkObservationJSON(t, v)
	})
}
func checkOptionalJSON(t testing.TB, v OptionalRecord) {
	t.Helper()
	want, we := json.Marshal(v)
	got, ge := MarshalOptionalRecord(v)
	if (we == nil) != (ge == nil) || we == nil && !bytes.Equal(want, got) {
		t.Fatalf("optional mismatch %v %v\n%s\n%s", we, ge, want, got)
	}
	p := OptionalPayload{domain.ID{1}, ^domain.U64(0), 1, v}
	want, we = json.Marshal(p)
	got, ge = MarshalOptionalPayload(p)
	if (we == nil) != (ge == nil) || we == nil && !bytes.Equal(want, got) {
		t.Fatal("optional payload mismatch", we, ge)
	}
}
func TestGeneratedOptionalJSON(t *testing.T) {
	v := optionalFixture()
	checkOptionalJSON(t, v)
	v.Board = &v.Site
	v.Operation = &v.ID
	v.UserAgent = &HeaderValue{"<>日本語", string([]byte{255})}
	n := uint16(65535)
	v.TLSVersion = &n
	v.TLSCipher = &n
	checkOptionalJSON(t, v)
	v.ID = domain.ID{}
	checkOptionalJSON(t, v)
}
func FuzzGeneratedOptionalJSON(f *testing.F) {
	base := optionalFixture()
	f.Add("<&>日本語\n", int64(1))
	f.Fuzz(func(t *testing.T, s string, n int64) {
		v := base
		v.Received = domain.Time(n)
		v.UserAgent = &HeaderValue{s, s}
		v.Route = s
		v.Status = int(n)
		checkOptionalJSON(t, v)
	})
}
func BenchmarkGeneratedObservationJSON(b *testing.B) {
	v := decodedObservationFixture(b)
	v.SelectedHeaders = []ObservedHeader{{"User-Agent", "http_parser", []HeaderValue{{"YWJj", strings.Repeat("合成UserAgent", 20)}}}}
	for _, kind := range []string{"standard", "direct", "bound"} {
		b.Run(kind, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				var err error
				switch kind {
				case "standard":
					_, err = json.Marshal(v)
				case "direct":
					_, err = MarshalHTTPObservation(v)
				case "bound":
					_, err = HTTPObservationJSONBound(v, 128<<10)
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestGeneratedObservationSizeFallback は上界だけが大きい正当な値も正確な長さで受け付ける。
func TestGeneratedObservationSizeFallback(t *testing.T) {
	v := decodedObservationFixture(t)
	text := strings.Repeat("<", 16000)
	v.SelectedHeaders = []ObservedHeader{{Name: "User-Agent", Representation: "http_parser", Values: []HeaderValue{encodeHeaderValue(text)}}}
	v.ParsedHeaderBytes = domain.U64(len("User-Agent") + len(text) + 4)
	bound, e := HTTPObservationJSONBound(v, 128<<10)
	if e != nil || bound <= 128<<10 {
		t.Fatal("fallback fixture did not exceed bound", bound, e)
	}
	raw, e := json.Marshal(v)
	if e != nil || len(raw) > 128<<10 || ValidateHTTPObservation(raw) != nil || ValidateHTTPObservationValue(v) != nil {
		t.Fatal("safe fallback rejected", len(raw), e)
	}
	if _, e = HTTPObservationJSONBound(v, -1); e == nil {
		t.Fatal("negative bound accepted")
	}
	if _, e = HTTPObservationJSONBound(v, int(^uint(0)>>1)); e == nil {
		t.Fatal("overflow bound accepted")
	}
}
