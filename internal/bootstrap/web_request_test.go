// 機能試験のWeb要求で圧縮対応を宣言し、比較しやすいidentity表現を優先する。
package bootstrap

import (
	"io"
	"net/http"
	"net/http/httptest"
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
