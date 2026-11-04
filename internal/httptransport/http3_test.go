// HTTP/3の実UDP応答、TCPとの共用、待受失敗時の継続を検査する。
package httptransport

import (
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTP3DisabledAndUDPBusy(t *testing.T) {
	testHTTP3Disabled(t, Prepare)
}

func TestHTTP3UDPStopKeepsHTTP2AndClearsAdvertisement(t *testing.T) {
	tcp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("alive")) }))
	tcp.EnableHTTP2 = true
	certificate := httptest.NewTLSServer(nil)
	tcp.TLS = certificate.TLS.Clone()
	tcp.TLS.NextProtos = []string{"h2", "http/1.1"}
	certificate.Close()
	tcp.Config.TLSConfig = tcp.TLS
	h3, reason, err := Prepare(tcp.Config, tcp.Listener.Addr(), "https://"+tcp.Listener.Addr().String(), true, 16, 4)
	if err != nil || h3 == nil {
		t.Fatalf("%s: %v", reason, err)
	}
	defer h3.Close()
	done := make(chan error, 1)
	go func() { done <- h3.Serve() }()
	tcp.StartTLS()
	defer tcp.Close()
	deadline := time.Now().Add(time.Second)
	for !h3.active.Load() {
		if time.Now().After(deadline) {
			t.Fatal("HTTP/3 did not start")
		}
		time.Sleep(time.Millisecond)
	}
	response, err := tcp.Client().Get(tcp.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.ProtoMajor != 2 || response.Header.Get("Alt-Svc") == "" || response.Header.Get("Alt-Svc") == "clear" {
		t.Fatalf("HTTP/3 advertisement: protocol=%s Alt-Svc=%q", response.Proto, response.Header.Get("Alt-Svc"))
	}
	if err = h3.listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err = <-done; !errors.Is(err, http.ErrServerClosed) {
		t.Fatal(err)
	}
	response, err = tcp.Client().Get(tcp.URL)
	if err != nil {
		t.Fatal("TCP stopped with UDP", err)
	}
	response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 || response.Header.Get("Alt-Svc") != "clear" {
		t.Fatal("HTTP/2 fallback or Alt-Svc clearing failed")
	}
}
func testHTTP3Disabled(t *testing.T, prepare func(*http.Server, net.Addr, string, bool, int, int) (*HTTP3, string, error)) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	server := &http.Server{TLSConfig: &tls.Config{}, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})}
	for _, enabled := range []bool{false, true} {
		h3, reason, err := prepare(server, udp.LocalAddr(), "https://example.test:443", enabled, 16, 4)
		if err != nil || h3 != nil || reason == "" {
			t.Fatalf("enabled=%v h3=%v reason=%s err=%v", enabled, h3, reason, err)
		}
		rr := httptest.NewRecorder()
		server.Handler.ServeHTTP(rr, httptest.NewRequest("GET", "https://example.test", nil))
		if rr.Header().Get("Alt-Svc") != "" {
			t.Fatal("unavailable UDP advertised")
		}
	}
}

// UDPを確保できない起動でも、同じportのTCP/TLSからHTTP/2応答を取得できる。
func TestHTTP3UDPBusyStartsHTTP2(t *testing.T) {
	tcp := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("alive")) }))
	tcp.EnableHTTP2 = true
	certificate := httptest.NewTLSServer(nil)
	tcp.TLS = certificate.TLS.Clone()
	tcp.TLS.NextProtos = []string{"h2", "http/1.1"}
	certificate.Close()
	tcp.Config.TLSConfig = tcp.TLS
	udp, err := net.ListenPacket("udp", tcp.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	h3, reason, err := Prepare(tcp.Config, tcp.Listener.Addr(), "https://"+tcp.Listener.Addr().String(), true, 16, 4)
	if err != nil || h3 != nil || reason == "" {
		t.Fatalf("UDP busy did not select TCP: h3=%v reason=%s error=%v", h3, reason, err)
	}
	tcp.StartTLS()
	defer tcp.Close()
	response, err := tcp.Client().Get(tcp.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != 200 || response.Header.Get("Alt-Svc") != "" {
		t.Fatal("HTTP/2 startup fallback failed")
	}
}
