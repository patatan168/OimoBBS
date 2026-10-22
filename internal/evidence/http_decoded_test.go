// HTTP観測値を再利用しても、完全型・サイズ・業務制約が維持されることを検査する。
package evidence

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
)

func decodedObservationFixture(t testing.TB) HTTPObservation {
	t.Helper()
	observer, e := NewHTTPObserver(domain.ID{1}, domain.ID{2}, "test-build")
	if e != nil {
		t.Fatal(e)
	}
	request := httptest.NewRequest("POST", "http://example.test/", http.NoBody)
	conn := observationConn{peer: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345}, local: &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}}
	request = request.WithContext(observer.ConnContext(request.Context(), conn))
	capture, e := observer.Begin(request, domain.ID{3}, "bbs_post", "example.test")
	if e != nil {
		t.Fatal(e)
	}
	v, e := capture.Finish()
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestDecodedObservationValidation(t *testing.T) {
	good := decodedObservationFixture(t)
	for _, change := range []func(*HTTPObservation){func(*HTTPObservation) {}, func(v *HTTPObservation) { v.BodyCompleted = 0 }, func(v *HTTPObservation) { v.BoardID = domain.ID{} }, func(v *HTTPObservation) { v.SiteID = domain.ID{} }, func(v *HTTPObservation) { v.Method = "GET" }, func(v *HTTPObservation) { v.ParsedHeaderBytes = MaxObservedHeaderBytes + 1 }, func(v *HTTPObservation) { v.ServerBuildID = strings.Repeat("x", 129<<10) }} {
		v := good
		change(&v)
		raw, marshalErr := json.Marshal(v)
		want := marshalErr == nil && ValidateHTTPObservation(raw) == nil
		if (ValidateHTTPObservationValue(v) == nil) != want {
			t.Fatal("value validator changed acceptance")
		}
		got, e := DecodeHTTPObservation(raw)
		if (e == nil) != want || e == nil && !reflect.DeepEqual(got, v) {
			t.Fatal("decoded value differs", e)
		}
		if e != nil && !reflect.DeepEqual(got, HTTPObservation{}) {
			t.Fatal("invalid observation returned")
		}
	}
}

func FuzzDecodedObservationEquivalence(f *testing.F) {
	raw, e := json.Marshal(decodedObservationFixture(f))
	if e != nil {
		f.Fatal(e)
	}
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var value HTTPObservation
		if strictjson.Decode(raw, &value) != nil {
			return
		}
		canonical, e := json.Marshal(value)
		want := e == nil && ValidateHTTPObservation(canonical) == nil
		if (ValidateHTTPObservationValue(value) == nil) != want {
			t.Fatalf("decoded value acceptance differs: %q", raw)
		}
	})
}
