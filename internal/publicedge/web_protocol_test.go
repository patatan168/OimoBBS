// edgeが利用者側のHTTP世代を検査し、HTTP/2の保存側へ隠して転送しないことを実TLSで検証する。
package publicedge

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestEdgeModernHTTPWithHTTP2Upstream(t *testing.T) {
	var calls atomic.Int64
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.ProtoMajor != 2 {
			t.Error("upstream did not use HTTP/2", r.Proto)
		}
		w.WriteHeader(204)
	}))
	backend.EnableHTTP2 = true
	backend.StartTLS()
	defer backend.Close()
	upstream, _ := url.Parse(backend.URL)
	h, err := handler("https://bbs.example", upstream, backend.Client().Transport, "/admin")
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewUnstartedServer(h)
	front.EnableHTTP2 = true
	front.StartTLS()
	defer front.Close()
	for _, h2 := range []bool{false, true} {
		t.Run(fmt.Sprint(h2), func(t *testing.T) {
			transport := front.Client().Transport.(*http.Transport).Clone()
			transport.ForceAttemptHTTP2 = h2
			if !h2 {
				transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
				transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			for _, path := range []string{"/", "/web/post", "/admin/login", "/admin/SETTING.TXT", "/admin/dat/1.dat", "/_edge/health", "/bbsmenu.json", "/test/bbs.cgi", "/oimo/subject.txt", "/oimo/dat/1.dat"} {
				for _, method := range []string{"GET", "HEAD", "POST"} {
					r, _ := http.NewRequest(method, front.URL+path, nil)
					r.Host = "bbs.example"
					r.Header.Set("Accept-Encoding", "gzip")
					before := calls.Load()
					res, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(res.Body)
					res.Body.Close()
					want, forwarded := 505, false
					if h2 || path == "/bbsmenu.json" || path == "/test/bbs.cgi" || path == "/oimo/subject.txt" || path == "/oimo/dat/1.dat" {
						want, forwarded = 204, true
						if path == "/_edge/health" && method == "GET" {
							want, forwarded = 200, false
						}
					}
					if err != nil || res.StatusCode != want || (res.ProtoMajor == 2) != h2 || (calls.Load() > before) != forwarded || len(body) != 0 {
						t.Fatal(method, path, res.Status, res.Proto, "forwarded", calls.Load()-before, err)
					}
					if want == 505 && res.Header.Get("Cache-Control") != "no-store" {
						t.Fatal("cacheable protocol rejection")
					}
				}
			}
		})
	}
}
