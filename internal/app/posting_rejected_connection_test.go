// 実HTTP観測の接続情報を保持し、未受理入力/資格を7日記録へコピーしないことを検査する。
package app

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"reflect"
	"testing"
)

func TestRejectedConnectionProjectionKeepsObservationWithoutInput(t *testing.T) {
	f := newRetirementFixture(t)
	i := f.identity
	i.Outcome = "not_accepted"
	obs := rejectedObservedRequest(t, f.owner)
	capture, e := json.Marshal(map[string]any{"schema": "form-post-v5", "observation": obs, "input": map[string]string{"body": "private-unaccepted-body", "name": "private-unaccepted-name"}, "token": "private-token", "cap": "private-cap"})
	if e != nil {
		t.Fatal(e)
	}
	v, e := buildRejectedConnection(i, capture)
	if e != nil || !reflect.DeepEqual(v.Observation, &obs) {
		t.Fatal("connection changed", e)
	}
	v.Owner, v.Day, v.Seq = f.owner, 20231114, 5
	v.Decided = i.Committed
	raw, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	if e = validateRejectedConnection(raw); e != nil {
		t.Fatal(e)
	}
	assertRejectedSecretsAbsent(t, raw)
	var unknown map[string]any
	_ = json.Unmarshal(raw, &unknown)
	unknown["input"] = map[string]string{"body": "private-unaccepted-body"}
	tampered, _ := json.Marshal(unknown)
	if e = validateRejectedConnection(tampered); e == nil {
		t.Fatal("body field accepted in connection record")
	}
}

func assertRejectedSecretsAbsent(t *testing.T, raw []byte) {
	t.Helper()
	for _, secret := range []string{"private-unaccepted-body", "private-unaccepted-name", "private-token", "private-cap", "private-cookie", "private-auth"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("private content copied to connection record")
		}
	}
}

func rejectedObservedRequest(t *testing.T, owner domain.ID) evidence.HTTPObservation {
	t.Helper()
	observer, e := evidence.NewHTTPObserver(domain.NewID(), domain.NewID(), "test-build")
	if e != nil {
		t.Fatal(e)
	}
	observations := make(chan evidence.HTTPObservation, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture, e := observer.Begin(r, owner, "bbs_post", "example.test")
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if _, e = io.Copy(io.Discard, r.Body); e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		obs, e := capture.Finish()
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		observations <- obs
		w.WriteHeader(204)
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	response := sendRejectedObservedRequest(t, server)
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	response.Body.Close()
	return <-observations
}

func sendRejectedObservedRequest(t *testing.T, server *httptest.Server) *http.Response {
	t.Helper()
	request, e := http.NewRequest("POST", server.URL+"/test/bbs.cgi", bytes.NewBufferString("body=private-unaccepted-body"))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Set("Cookie", "private-cookie")
	request.Header.Set("Authorization", "Bearer private-auth")
	response, e := server.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	return response
}
