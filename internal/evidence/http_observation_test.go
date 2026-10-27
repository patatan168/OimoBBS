// 実TCPで観測する接続ID・IP/portと、秘密を含まないHTTP記録を検査する。
package evidence

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"strings"
	"sync"
	"testing"
)

func testObserver(t *testing.T) *HTTPObserver {
	t.Helper()
	o, e := NewHTTPObserver(domain.NewID(), domain.NewID(), "test-build")
	if e != nil {
		t.Fatal(e)
	}
	return o
}
func TestHTTPObservationRealConnection(t *testing.T) {
	observer := testObserver(t)
	observations := make(chan HTTPObservation, 2)
	owner := domain.NewID()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture, e := observer.Begin(r, owner, "bbs_post", "example.test")
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if _, e = io.Copy(io.Discard, r.Body); e != nil {
			t.Error(e)
			return
		}
		observation, e := capture.Finish()
		if e != nil {
			t.Error(e)
			return
		}
		observations <- observation
		w.WriteHeader(204)
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	client := server.Client()
	for range 2 {
		request, e := http.NewRequest("POST", server.URL+"/test/bbs.cgi?secret=query-secret", bytes.NewBufferString("password=body-secret"))
		if e != nil {
			t.Fatal(e)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
		request.Header.Set("Cookie", "private-cookie")
		request.Header.Set("Authorization", "Bearer auth-secret")
		request.Header.Set("Referer", "https://example.test/private?secret=ref-secret")
		request.Header.Set("X-Forwarded-For", "198.51.100.2")
		request.Header.Set("User-Agent", "client-agent")
		response, e := client.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != 204 {
			t.Fatal(response.StatusCode)
		}
	}
	first, second := <-observations, <-observations
	if first.ConnectionID != second.ConnectionID || first.RequestID == second.RequestID {
		t.Fatal("connection/request identity")
	}
	if first.Peer.IP != "127.0.0.1" || first.Peer.Port == 0 || first.Local.Port == 0 || first.Resolved != first.Peer {
		t.Fatal("untrusted forwarded address adopted")
	}
	if first.BodyBytes != domain.U64(len("password=body-secret")) {
		t.Fatal("observation fields")
	}
	raw, e := json.Marshal(first)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateHTTPObservation(raw); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"body-secret", "private-cookie", "auth-secret", "ref-secret", "query-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret persisted")
		}
	}
	if len(first.ReportedHeaders) != 1 || len(first.SelectedHeaders) != 2 {
		t.Fatal("headers omitted", string(raw))
	}
}
func TestObservationRequiresRealSocketContext(t *testing.T) {
	observer := testObserver(t)
	request := httptest.NewRequest("POST", "http://example.test/", bytes.NewBufferString("x"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if _, e := observer.Begin(request, domain.NewID(), "bbs_post", "example.test"); e == nil {
		t.Fatal("invented connection accepted")
	}
}

func TestHTTP2ObservationSharesTLSConnection(t *testing.T) {
	observer := testObserver(t)
	owner := domain.NewID()
	seen := make(chan HTTPObservation, 5)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture, e := observer.Begin(r, owner, "web_reply", "example.test")
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if _, e = io.Copy(io.Discard, r.Body); e != nil {
			t.Error(e)
			return
		}
		observation, e := capture.Finish()
		if e != nil {
			t.Error(e)
			return
		}
		seen <- observation
		w.WriteHeader(204)
	}))
	server.EnableHTTP2 = true
	server.Config.ConnContext = observer.ConnContext
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Transport.(*http.Transport).MaxConnsPerHost = 1
	send := func() {
		r, e := client.Post(server.URL, "application/x-www-form-urlencoded", bytes.NewBufferString("x=y"))
		if e != nil {
			t.Error(e)
			return
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 204 {
			t.Error(r.StatusCode)
		}
	}
	send()
	if t.Failed() {
		return
	}
	first := <-seen
	var wait sync.WaitGroup
	for range 4 {
		wait.Go(send)
	}
	wait.Wait()
	if t.Failed() {
		return
	}
	ids := map[domain.ID]bool{first.RequestID: true}
	for range 4 {
		v := <-seen
		if v.ConnectionID != first.ConnectionID || ids[v.RequestID] || v.HTTPVersion != "HTTP/2.0" || v.TLSVersion == nil || v.TLSCipherSuite == nil {
			t.Fatal("HTTP/2 connection metadata", v)
		}
		ids[v.RequestID] = true
		raw, _ := json.Marshal(v)
		if e := ValidateHTTPObservation(raw); e != nil {
			t.Fatal(e)
		}
	}
}

type observationConn struct {
	net.Conn
	peer, local net.Addr
}

func (c observationConn) RemoteAddr() net.Addr { return c.peer }
func (c observationConn) LocalAddr() net.Addr  { return c.local }
func observationRequest(t *testing.T, body io.ReadCloser) (*HTTPObserver, *http.Request) {
	t.Helper()
	observer := testObserver(t)
	request := httptest.NewRequest("POST", "http://example.test/", nil)
	request.Body = body
	conn := observationConn{peer: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 12345}, local: &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 443}}
	request = request.WithContext(observer.ConnContext(request.Context(), conn))
	return observer, request
}
func TestObservationHeaderPrivacyAndStrictSchema(t *testing.T) {
	observer, r := observationRequest(t, http.NoBody)
	rawUA := string([]byte{'a', 255, 'b'})
	r.Header.Set("User-Agent", rawUA)
	r.Header.Set("Origin", "https://user:password-secret@example.test:443/private-path?query-secret=x#fragment-secret")
	r.Header.Set("X-Unknown", "unknown-secret")
	capture, e := observer.Begin(r, domain.NewID(), "web_create", "example.test")
	if e != nil {
		t.Fatal(e)
	}
	v, e := capture.Finish()
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if e = ValidateHTTPObservation(raw); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"password-secret", "private-path", "query-secret", "fragment-secret", "unknown-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret stored")
		}
	}
	if v.Peer.IP != "2001:db8::1" {
		t.Fatal("IPv6 truncated")
	}
	ua := v.SelectedHeaders[1].Values[0]
	decoded, e := base64.StdEncoding.DecodeString(ua.Base64)
	if e != nil || string(decoded) != rawUA || ua.Display != "a�b" {
		t.Fatal("header bytes lost")
	}
	var fields map[string]json.RawMessage
	if e = json.Unmarshal(raw, &fields); e != nil {
		t.Fatal(e)
	}
	delete(fields, "local")
	bad, _ := json.Marshal(fields)
	if e = ValidateHTTPObservation(bad); e == nil {
		t.Fatal("missing field accepted")
	}
	if _, e = capture.Finish(); e == nil {
		t.Fatal("capture reused")
	}
	v.Resolved.IP = "198.51.100.3"
	bad, _ = json.Marshal(v)
	if e = ValidateHTTPObservation(bad); e == nil {
		t.Fatal("reported IP trusted")
	}
}
func TestObservationBodyAndHeaderLimits(t *testing.T) {
	for _, mode := range []string{"unread", "close", "too_large", "headers", "read_error"} {
		t.Run(mode, func(t *testing.T) {
			body := io.NopCloser(bytes.NewBufferString("x=y"))
			if mode == "too_large" {
				body = io.NopCloser(bytes.NewReader(bytes.Repeat([]byte{'x'}, MaxObservedBodyBytes+1)))
			}
			if mode == "read_error" {
				body = io.NopCloser(errorBody{})
			}
			observer, r := observationRequest(t, body)
			if mode == "headers" {
				r.Header.Set("Cookie", strings.Repeat("x", MaxObservedHeaderBytes))
			}
			capture, e := observer.Begin(r, domain.NewID(), "bbs_post", "example.test")
			if mode == "headers" {
				if e == nil {
					t.Fatal("oversize headers accepted")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if mode == "close" {
				r.Body.Close()
			}
			if mode == "too_large" || mode == "read_error" {
				if _, e = io.Copy(io.Discard, r.Body); e == nil {
					t.Fatal("read should fail")
				}
			}
			if _, e = capture.Finish(); e == nil {
				t.Fatal("incomplete body accepted")
			}
		})
	}
}

type errorBody struct{}

func (errorBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestReportedHeaderCanonicalNames(t *testing.T) {
	observer, r := observationRequest(t, http.NoBody)
	names := []string{"Forwarded", "X-Forwarded-For", "X-Real-IP", "X-Oimo-Client-IP", "X-Oimo-Client-Port", "X-Oimo-Destination-IP", "X-Oimo-Destination-Port", "X-Oimo-Edge-Request-ID", "X-Oimo-Edge-Time"}
	for _, name := range names {
		r.Header.Set(name, "untrusted-claim")
	}
	capture, e := observer.Begin(r, domain.NewID(), "bbs_post", "example.test")
	if e != nil {
		t.Fatal(e)
	}
	v, e := capture.Finish()
	if e != nil {
		t.Fatal(e)
	}
	if len(v.ReportedHeaders) != len(names) || v.Resolved != v.Peer {
		t.Fatal("reported fields dropped or trusted")
	}
	found := map[string]bool{}
	for _, h := range v.ReportedHeaders {
		found[h.Name] = true
		if h.Values[0].Display != "untrusted-claim" {
			t.Fatal("reported value changed")
		}
	}
	for _, name := range names {
		if !found[http.CanonicalHeaderKey(name)] {
			t.Fatal("reported header omitted", name)
		}
	}
}

func TestLegacyRoutingObservationBinding(t *testing.T) {
	observer := testObserver(t)
	owner := domain.NewID()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture, e := observer.BeginLegacyRouting(r, "example.test")
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if _, e = capture.FinishForBoard(owner); e == nil {
			t.Error("unread body accepted")
		}
		if _, e = io.Copy(io.Discard, r.Body); e != nil {
			t.Error(e)
		}
		if _, e = capture.Finish(); e == nil {
			t.Error("unresolved board accepted")
		}
		if _, e = capture.FinishForBoard(domain.ID{}); e == nil {
			t.Error("zero board accepted")
		}
		observation, e := capture.FinishForBoard(owner)
		if e != nil || observation.BoardID != owner || observation.BodyBytes != 8 {
			t.Error("binding failed", e)
		}
		raw, _ := json.Marshal(observation)
		if e = ValidateHTTPObservation(raw); e != nil {
			t.Error(e)
		}
		if _, e = capture.FinishForBoard(domain.NewID()); e == nil {
			t.Error("board rebound")
		}
		w.WriteHeader(204)
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	r, e := server.Client().Post(server.URL+"/test/bbs.cgi", "application/x-www-form-urlencoded", strings.NewReader("bbs=beta"))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 204 {
		t.Fatal(r.StatusCode)
	}
}
