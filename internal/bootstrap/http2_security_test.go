// 実TLSのHTTP/2設定通知と通常GETを照合し、受理前のstream/window制限を検査する。
package bootstrap

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublicHTTP2SecuritySettings(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	configured, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(configured.Handler)
	server.EnableHTTP2 = true
	server.Config.HTTP2 = configured.HTTP2
	repo.cfg.Public.BaseURL = "https://" + server.Listener.Addr().String()
	server.Config.Handler = repo.SiteWebHandler(nil)
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("HTTP/2 not negotiated")
	}
	if _, err := io.WriteString(conn, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"+string([]byte{0, 0, 0, 4, 0, 0, 0, 0, 0})); err != nil {
		t.Fatal(err)
	}
	var header [9]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	size := int(header[0])<<16 | int(header[1])<<8 | int(header[2])
	if header[3] != 4 || header[4] != 0 || binary.BigEndian.Uint32(header[5:]) != 0 || size > 1024 || size%6 != 0 {
		t.Fatal("invalid initial SETTINGS", header)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatal(err)
	}
	settings := map[uint16]uint32{}
	for i := 0; i < len(body); i += 6 {
		settings[binary.BigEndian.Uint16(body[i:])] = binary.BigEndian.Uint32(body[i+2:])
	}
	if settings[3] != 32 || settings[4] != 64<<10 || settings[5] != 16<<10 {
		t.Fatal("unbounded HTTP/2 settings", settings)
	}
	conn.Close()
	request, err := http.NewRequest("GET", server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.ProtoMajor != 2 {
		t.Fatal("ordinary HTTP/2 request rejected", response.Status, response.Proto)
	}
}
