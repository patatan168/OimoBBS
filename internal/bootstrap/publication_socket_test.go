// 実HTTP接続の送信途中に削除し、失効後の追加chunkがソケットへ出ないことを検査する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/delivery"
)

func TestPublicationSocketRevocation(t *testing.T) {
	for _, budget := range []uint64{80_000_000} {
		for _, protocol := range []string{"http1", "http2"} {
			t.Run(fmt.Sprintf("%s-budget-%d", protocol, budget), func(t *testing.T) { testPublicationSocketRevocation(t, protocol == "http2", budget) })
		}
	}
}

func testPublicationSocketRevocation(t *testing.T, http2 bool, budget uint64) {
	_, r := adminFixture(t)
	defer r.Close()
	info, e := r.CreateBoard(context.Background(), "socket", "送信検査")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, r, siteID(r.site.State()), info.ID)
	defer form.Close()
	accepted, e := sendForm(form, url.Values{"bbs": {"socket"}, "subject": {"old title"}, "MESSAGE": {"old body"}, "oimo_request_id": {"socket-create-0001"}})
	if e != nil || !accepted.Accepted {
		t.Fatal(accepted, e)
	}
	snapshot, e := r.Thread(context.Background(), info.ID, accepted.Key)
	if e != nil {
		t.Fatal(e)
	}
	ready, release := make(chan struct{}), make(chan struct{})
	finished := make(chan error, 1)
	streamContext := make(chan context.Context, 1)
	scheduler, e := delivery.New(budget)
	if e != nil {
		t.Fatal(e)
	}
	defer scheduler.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Test-Connection", req.RemoteAddr)
		if req.URL.Path == "/health" {
			w.WriteHeader(200)
			return
		}
		response, e := publicWriter(w, req, snapshot, time.Now)
		if e != nil {
			finished <- e
			return
		}
		defer response.Close()
		if _, e = response.Write([]byte("already-sent\n")); e != nil {
			finished <- e
			return
		}
		if e = http.NewResponseController(response).Flush(); e != nil {
			finished <- e
			return
		}
		streamContext <- req.Context()
		close(ready)
		<-release
		if e = http.NewResponseController(response).Flush(); !errors.Is(e, app.ErrPublicationGone) && !errors.Is(e, context.Canceled) {
			finished <- fmt.Errorf("flush after revoke: %v", e)
			return
		}
		_, e = response.Write([]byte("must-not-be-sent:old body"))
		finished <- e
	})
	server := httptest.NewUnstartedServer(scheduler.Wrap(handler))
	server.EnableHTTP2 = http2
	if http2 {
		server.StartTLS()
	} else {
		server.Start()
	}
	defer server.Close()
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	server.Client().Timeout = 15 * time.Second
	response, e := server.Client().Get(server.URL)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("first send did not complete")
	}
	if response.ProtoMajor != map[bool]int{false: 1, true: 2}[http2] {
		t.Fatal("wrong protocol", response.Proto)
	}
	first := make([]byte, len("already-sent\n"))
	if _, e = io.ReadFull(response.Body, first); e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		unblock()
		t.Fatal("login")
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", info.ID, accepted.Key)
	res, _ := client.request("GET", path, "", nil)
	if err := (<-streamContext).Err(); err != nil {
		t.Fatal("stream ended before moderation", err)
	}
	res, body := client.request("POST", path, `{"kind":"hide","ranges":[],"hide_title":false}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"socket-hide-000001"}})
	unblock()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	select {
	case e = <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("revoked writer did not complete")
	}
	if !errors.Is(e, app.ErrPublicationGone) && !errors.Is(e, context.Canceled) {
		t.Fatal("write after revoke", e)
	}
	remainder, _ := io.ReadAll(response.Body)
	if string(first) != "already-sent\n" || strings.Contains(string(remainder), "must-not-be-sent") {
		t.Fatal("revoked bytes transmitted", string(remainder))
	}
	if http2 {
		res, err := server.Client().Get(server.URL + "/health")
		if err != nil {
			t.Fatal("revocation broke unrelated HTTP2 stream", err)
		}
		res.Body.Close()
		if res.ProtoMajor != 2 || res.StatusCode != 200 || res.Header.Get("X-Test-Connection") != response.Header.Get("X-Test-Connection") {
			t.Fatal("unrelated stream failed", res.Proto, res.StatusCode)
		}
	}
}
