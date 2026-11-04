// 機能試験のWeb要求で圧縮対応を宣言し、比較しやすいidentity表現を優先する。
package bootstrap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// webReadTestRequest は本文の比較用にidentityを優先し、gzipの受け入れも宣言する。
// 圧縮受け入れ必須化の拒否試験では、httptest.NewRequestを直接使う。
func webReadTestRequest(method, target string, body io.Reader) *http.Request {
	r := httptest.NewRequest(method, target, body)
	if method == http.MethodGet || method == http.MethodHead {
		r.Header.Set("Accept-Encoding", "gzip;q=0.1")
	}
	return r
}

// modernWebReadTestRequest は公開組立ての機能試験用にHTTP/2相当の要求を作る。
// 実通信の検証にはmodernHTTPTestServerまたはTLSサーバーを使う。
func modernWebReadTestRequest(method, target string, body io.Reader) *http.Request {
	r := webReadTestRequest(method, target, body)
	r.Proto, r.ProtoMajor, r.ProtoMinor = "HTTP/2.0", 2, 0
	return r
}

// modernHTTPTestServer は隔離HTTP originの機能試験を実HTTP/2で起動する。
// TLS・旧HTTPの拒否試験と区別し、本文・Cookie・観測は実socketを通す。
func modernHTTPTestServer(t *testing.T, configured *http.Server) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(configured.Handler)
	server.Config.ConnContext = configured.ConnContext
	server.Config.HTTP2 = configured.HTTP2
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetUnencryptedHTTP2(true)
	server.Config.Protocols = protocols
	server.Start()
	clientProtocols := new(http.Protocols)
	clientProtocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: clientProtocols}
	t.Cleanup(transport.CloseIdleConnections)
	server.Client().Transport = transport
	return server
}
