// 実HTTPで収集した観測成分を永続投稿へ渡し、署名journalから再読込する。
package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func withPostingIP(t *testing.T, frame []byte, ip string) []byte {
	t.Helper()
	f, _, e := store.ReadFrame(bytes.NewReader(frame))
	if e != nil {
		t.Fatal(e)
	}
	op, e := domain.ParseOperation(f.Records[0].JSON)
	if e != nil {
		t.Fatal(e)
	}
	var create domain.Create
	if e = json.Unmarshal(op.Payload, &create); e != nil {
		t.Fatal(e)
	}
	create.Posts[0].Private.SourceIP = ip
	op.Payload, _ = json.Marshal(create)
	f.Records[0].JSON, _ = json.Marshal(op)
	result, e := store.EncodeFrame(f)
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func TestHTTPObservationDurablePosting(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "HTTP観測試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, evidence.ValidateHTTPObservation)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	observer, e := evidence.NewHTTPObserver(report.SiteID, domain.NewID(), "integration-test")
	if e != nil {
		t.Fatal(e)
	}
	observations := make(chan evidence.HTTPObservation, 1)
	results := make(chan RepositoryPostingResult, 1)
	// 受付翌日に処理された要求でも、記録の所有日は受付UTC日付を使う。
	queued := time.Now().AddDate(0, 0, 1)
	repo.posting[info.ID].clock = func() time.Time { return queued }
	var frame []byte
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capture, e := observer.Begin(r, info.ID, "bbs_post", "example.test")
		if e != nil {
			t.Error(e)
			w.WriteHeader(500)
			return
		}
		if _, e = io.Copy(io.Discard, r.Body); e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		observation, e := capture.Finish()
		if e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		// 投稿構築・認可の試験ではないため、既存の確定済み入力fixtureを使用する。
		frame = withPostingIP(t, persistentFrame(t), observation.Peer.IP)
		raw, e := json.Marshal(observation)
		if e != nil {
			t.Error(e)
			return
		}
		result := repo.Post(r.Context(), info.ID, 0, frame, raw)
		results <- result
		observations <- observation
		if result.Status != store.Durable {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(204)
	}))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	defer server.Close()
	request, e := http.NewRequest("POST", server.URL+"/test/bbs.cgi?query-secret=x", bytes.NewBufferString("body=hello&csrf=form-secret"))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	request.Header.Set("Authorization", "Bearer header-secret")
	request.Header.Set("Cookie", "cookie-secret")
	response, e := server.Client().Do(request)
	if e != nil {
		t.Fatal(e)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 204 {
		t.Fatal(response.StatusCode)
	}
	result, observation := <-results, <-observations
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	day, _ := strconv.ParseUint(time.Unix(0, int64(observation.Received)).UTC().Format("20060102"), 10, 64)
	entries := repo.posting[info.ID].journals[day].Entries()
	if len(entries) != 2 {
		t.Fatal("request not saved on reception date")
	}
	for _, secret := range []string{"query-secret", "form-secret", "header-secret", "cookie-secret"} {
		if bytes.Contains(entries[0].Payload, []byte(secret)) {
			t.Fatal("secret in durable proposal")
		}
	}
	wrong := observation
	wrong.SiteID = domain.NewID()
	raw, _ := json.Marshal(wrong)
	if r := repo.Post(context.Background(), info.ID, 0, frame, raw); r.Status != store.NotWritten || !errors.Is(r.Err, evidence.ErrHTTPObservation) {
		t.Fatal("wrong site observation accepted", r)
	}
	raw, _ = json.Marshal(observation)
	if r := repo.Post(context.Background(), info.ID, 0, withPostingIP(t, frame, "192.0.2.4"), raw); r.Status != store.NotWritten || !errors.Is(r.Err, evidence.ErrHTTPObservation) {
		t.Fatal("wrong post IP accepted", r)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer repo.Close()
	snapshot, e := repo.Thread(context.Background(), info.ID, result.ThreadKey)
	if e != nil || snapshot == nil || snapshot.PostCount != 1 {
		t.Fatal(snapshot, e)
	}
	days, e := postingNames(filepath.Join(cfg.DataDir, "evidence", info.ID.String()))
	if e != nil || len(days) != 1 || days[0] != day {
		t.Fatal(days, e)
	}
}
