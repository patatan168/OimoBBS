// 実HTTP/3の公開入口でendpoint上書き・非公開経路拒否・HTTP/2転送を検査する。
package publicedge

import (
	"io"

	"net/http"
	"net/http/httptest"

	"testing"
	"time"
)

func TestUpstreamTransportNegotiatesHTTP2(t *testing.T) {
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, r.Proto) }))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()
	tr := upstreamTransport("example.com", backend.TLS.Certificates[0])
	tr.TLSClientConfig.RootCAs = backend.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: time.Second}
	res, err := client.Get(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.ProtoMajor != 2 || string(body) != "HTTP/2.0" {
		t.Fatalf("upstream: %s %v", body, err)
	}
}
