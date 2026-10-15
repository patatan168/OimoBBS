// HTTPS固定が拒否応答にも適用され、HTTP管理へ漏れないことを検査する。
package bootstrap

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityTransportHeaders(t *testing.T) {
	for _, secure := range []bool{false, true} {
		r := httptest.NewRequest("GET", "http://localhost/", nil)
		if secure {
			r.TLS = &tls.ConnectionState{}
		}
		w := httptest.NewRecorder()
		securityTransportHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) })).ServeHTTP(w, r)
		if (w.Header().Get("Strict-Transport-Security") != "") != secure || w.Header().Get("Permissions-Policy") == "" || w.Code != 503 {
			t.Fatal("transport header boundary")
		}
	}
}
