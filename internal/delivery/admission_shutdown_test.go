// 停止中の新規受付拒否と受理済み要求の完了・枠解放を並行検査する。
package delivery

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestGateCloseDrainsAcceptedRequest(t *testing.T) {
	g, err := NewRequestGate(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	h := g.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(200)
	}))
	first := httptest.NewRecorder()
	go func() { h.ServeHTTP(first, httptest.NewRequest("GET", "/", nil)); close(done) }()
	<-started
	g.Close()
	g.Close()
	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest("GET", "/", nil))
	if second.Code != 503 || second.Header().Get("Retry-After") != "1" {
		t.Fatal(second.Code, second.Header())
	}
	close(release)
	<-done
	if first.Code != 200 {
		t.Fatal(first.Code)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.total != 0 || len(g.ips) != 0 {
		t.Fatal("admission slots leaked", g.total, g.ips)
	}
}
