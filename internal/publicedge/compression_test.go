// 公開edgeが圧縮受入の申告を保持し、専用healthcheckを転送しないことを検査する。
package publicedge

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestPublicEdgePreservesAcceptEncoding(t *testing.T) {
	upstream, _ := url.Parse("https://backend:8443")
	for _, values := range [][]string{nil, {"identity"}, {"gzip"}, {"zstd;q=0", "gzip;q=0.5"}} {
		t.Run(strings.Join(values, ","), func(t *testing.T) {
			called := false
			handler, err := Handler("https://bbs.example", upstream, transportFunc(func(r *http.Request) (*http.Response, error) {
				called = true
				if !slices.Equal(r.Header.Values("Accept-Encoding"), values) {
					t.Fatalf("compression declaration changed: got %q, want %q", r.Header.Values("Accept-Encoding"), values)
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest("GET", "https://bbs.example/", nil)
			request.RemoteAddr = "192.0.2.10:12345"
			request = request.WithContext(context.WithValue(request.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 8443}))
			for _, value := range values {
				request.Header.Add("Accept-Encoding", value)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if !called || response.Code != 200 {
				t.Fatal("public request was not forwarded", response.Code)
			}
			called = false
			request = httptest.NewRequest("GET", "https://bbs.example/_edge/health", nil)
			response = httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if called || response.Code != 200 || response.Body.Len() != 0 {
				t.Fatal("healthcheck was forwarded or rejected", response.Code)
			}
		})
	}
}
