// 実HTTPで投稿原本・明示権限・保全・部分出力・一回取得・再起動・解除を検証する。
package bootstrap

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func evidencePost(t *testing.T, c *adminClient, path string, input evidenceInput, etag, csrf, key string) (*http.Response, disclosure.Case, string) {
	t.Helper()
	raw, e := json.Marshal(input)
	if e != nil {
		t.Fatal(e)
	}
	res, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {etag}, "X-CSRF-Token": {csrf}, "Idempotency-Key": {key}})
	var v struct {
		Data disclosure.Case `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &v)
	return res, v.Data, body
}
func evidenceInfo(t *testing.T, c *adminClient, id domain.ID) (disclosure.Case, map[string]string) {
	t.Helper()
	res, body := c.request("GET", "/api/v1/evidence/cases/"+id.String(), "", nil)
	if res.StatusCode != 200 {
		t.Fatal("case GET", res.StatusCode, body)
	}
	var v struct {
		Data   []disclosure.Case `json:"data"`
		Tokens map[string]string `json:"csrf_tokens"`
	}
	if json.Unmarshal([]byte(body), &v) != nil || len(v.Data) != 1 {
		t.Fatal(body)
	}
	return v.Data[0], v.Tokens
}
func TestAdminEvidenceHTTPCompleteLifecycle(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	b, e := repo.CreateBoard(context.Background(), "logs", "ログ検証")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	if res, _ := client.request("GET", "/api/v1/evidence/cases", "", nil); res.StatusCode != 200 {
		t.Fatal("site admin missing inherited records grant", res.StatusCode)
	}
	if _, e = repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	client.server.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login after generation change")
	}
	if res, _ := client.request("GET", "/api/v1/evidence/cases", "", nil); res.StatusCode != 403 {
		t.Fatal("reauth not required")
	}
	if client.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	fs := formServer(t, repo, siteID(repo.site.State()), b.ID)
	defer fs.Close()
	posted, e := sendForm(fs, url.Values{"bbs": {"logs"}, "subject": {"記録確認"}, "FROM": {"投稿者#trip-secret-to-remove"}, "MESSAGE": {"PRIVATE-POST-BODY"}, "unknown": {"unknown-secret-to-remove"}, "oimo_request_id": {"evidence-create-01"}})
	if e != nil || !posted.Accepted {
		t.Fatal(posted, e)
	}
	now := time.Now()
	input := evidenceInput{Number: "CASE-001", Reason: "提出準備", Scope: disclosure.Scope{Board: b.ID, Thread: domain.U64(posted.Key), From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano()), Records: []domain.ID{}}}
	list, _ := client.request("GET", "/api/v1/evidence/cases", "", nil)
	create := "/api/v1/evidence/cases"
	key := domain.NewID().String()
	res, c, body := evidencePost(t, client, create, input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), key)
	if res.StatusCode != 200 || c.State != "draft" {
		t.Fatal("create", res.StatusCode, body)
	}
	res, replayed, _ := evidencePost(t, client, create, input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), key)
	if res.StatusCode != 200 || replayed.ID != c.ID {
		t.Fatal("creation repeat", res.StatusCode)
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	hold := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
	res, c, body = evidencePost(t, client, hold, evidenceInput{Reason: "明示保全"}, c.ETag(), tokens[hold], domain.NewID().String())
	if res.StatusCode != 200 || c.State != "active" || len(c.Items) != 1 {
		t.Fatal("hold", res.StatusCode, body)
	}
	if c.Required == nil || c.Required.Released == nil {
		t.Fatal("required source reservation/release missing")
	}
	bowner := repo.posting[b.ID]
	_, err := bowner.worker.Submit(t.Context(), func() (any, error) {
		receipt, found, e := bowner.requiredHolds.Receipt(c.ID)
		if e != nil || !found || receipt.State != "released" || receipt.SHA != c.Required.Released.SHA {
			return nil, fmt.Errorf("required release mismatch: %v", e)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	// 案件に対応する署名済みHTTP fixtureを追加し、接続列だけに返ることを検査する。
	public := optionalProductServer(t, repo)
	res, err = public.Client().Get(public.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	public.Close()
	if err = repo.optionalQueue.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	records := optionalProductRecords(t, cfg, siteID(repo.site.State()))
	if len(records) == 0 {
		t.Fatal("optional observation absent")
	}
	accepted, err := repo.collectEvidence(context.Background(), c.Scope)
	if err != nil || len(accepted) != 1 {
		t.Fatal(accepted, err)
	}
	optional := records[0]
	optional.ID = domain.NewID()
	optional.Board = &b.ID
	optional.Operation = &accepted[0].Operation
	optional.Received = accepted[0].Committed
	optional.Finished = optional.Received + 100
	optional.Until = optional.Received + domain.Time(evidence.OptionalRetention)
	optional.Method, optional.Route, optional.Kind, optional.Outcome = "POST", "legacy_post", "response", "accepted"
	bindAcceptedResponseFixture(t, &optional, accepted[0])
	if err = repo.optionalStore.Write(context.Background(), optional); err != nil {
		t.Fatal(err)
	}
	query := "/api/v1/evidence/query"
	res, c, body = evidencePost(t, client, query, evidenceInput{CaseID: c.ID, Reason: "接続照合", Columns: []string{"connection"}}, c.ETag(), tokens[query], domain.NewID().String())
	if res.StatusCode != 200 || !strings.Contains(body, "127.0.0.1") || strings.Contains(body, "PRIVATE-POST-BODY") || strings.Contains(body, "trip-secret-to-remove") {
		t.Fatal("private projection", res.StatusCode, body)
	}
	if !strings.Contains(body, optional.ID.String()) || !strings.Contains(body, "partial_observation") {
		t.Fatal("optional connection projection absent", body)
	}
	assertAcceptedResponseQuery(t, body, optional)

	// 正しい現在権限・再認証があっても、HTTP原本期限を過ぎた送信は開始しない。
	manager := repo.adminAuth
	repo.mu.Lock()
	admins, err := repo.administrators()
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var generation domain.U64
	for _, admin := range admins {
		if admin.ID == c.Creator {
			generation = admin.Generation
		}
	}
	cookie, session, err := manager.Create(c.Creator, generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, session, err = manager.MarkReauthenticated(cookie, session, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := &adminHandler{repo: repo}
	allowed := httptest.NewRecorder()
	if n, err := h.guardEvidenceQuery(allowed, session, c, nil).Write([]byte("allowed")); err != nil || n != 7 {
		t.Fatal("valid query guard refused", n, err)
	}
	expired := optional
	expired.Until = domain.Time(time.Now().Add(-time.Second).UnixNano())
	recorder := httptest.NewRecorder()
	guarded := h.guardEvidenceQuery(recorder, session, c, []map[string]any{{"optional_http": []evidence.OptionalEvidence{{Record: expired}}}})
	func() {
		defer func() {
			if recovered := recover(); recovered != http.ErrAbortHandler {
				t.Errorf("expired HTTP record did not stop query: %v", recovered)
			}
		}()
		guarded.Write([]byte("PRIVATE_HTTP_RECORD"))
	}()
	if recorder.Body.Len() != 0 {
		t.Fatal("expired query bytes transmitted")
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	httpHold := "/api/v1/evidence/cases/" + c.ID.String() + "/http-hold"
	repo.mu.Lock()
	source := repo.optionalStore
	heldCaseID := c.ID
	repo.optionalHoldAfterReserve = func() {
		if !repo.mu.TryLock() {
			t.Error("case mutex held after source reservation Sync")
			return
		}
		repo.mu.Unlock()
		receipt, found, e := source.OptionalHoldReceipt(heldCaseID)
		if e != nil || !found || receipt.State != "active" {
			t.Error("source reservation not durable before copy", receipt, found, e)
		}
	}
	repo.mu.Unlock()
	res, c, body = evidencePost(t, client, httpHold, evidenceInput{Reason: "関連HTTP保全"}, c.ETag(), tokens[httpHold], domain.NewID().String())
	if res.StatusCode != 200 || c.HTTP == nil || c.HTTP.State != "active" || c.HTTP.Reservation == nil || len(c.HTTP.Items) != 1 {
		t.Fatal("HTTP hold", res.StatusCode, body)
	}
	released, found, releaseErr := source.OptionalHoldReceipt(c.ID)
	if releaseErr != nil || !found || released.State != "released" || released.Sequence <= c.HTTP.Reservation.Sequence {
		t.Fatal("completed source reservation not released", released, found, releaseErr)
	}
	repo.mu.Lock()
	repo.optionalHoldAfterReserve = nil
	repo.mu.Unlock()
	repo.mu.Lock()
	var storedSite siteState
	err = json.Unmarshal(repo.site.State().Rows["site:state"].Value, &storedSite)
	repo.mu.Unlock()
	if err != nil || storedSite.MinimumReader != 46 {
		t.Fatal("HTTP hold reader gate", storedSite.MinimumReader, err)
	}
	if n, err := h.guardEvidenceQuery(httptest.NewRecorder(), session, c, []map[string]any{{"optional_http": []evidence.OptionalEvidence{{Record: expired}}}}).Write([]byte("held")); err != nil || n != 4 {
		t.Fatal("held copy used original expiry", n, err)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	res, c, body = evidencePost(t, client, query, evidenceInput{CaseID: c.ID, Reason: "本文だけ照会", Columns: []string{"content"}}, c.ETag(), tokens[query], domain.NewID().String())
	var selectedResult struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &selectedResult); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || bytes.Contains(selectedResult.Result, []byte(optional.ID.String())) || bytes.Contains(selectedResult.Result, []byte("optional_http")) {
		t.Fatal("unselected HTTP observation disclosed", res.StatusCode, body)
	}
	assertSelectedAcceptedDAT(t, selectedResult.Result, accepted[0].Proposal.Payload)
	c, tokens = evidenceInfo(t, client, c.ID)
	res, c, body = evidencePost(t, client, query, evidenceInput{CaseID: c.ID, Reason: "受理枠ルール照合", Columns: []string{"principal"}}, c.ETag(), tokens[query], domain.NewID().String())
	if err := json.Unmarshal([]byte(body), &selectedResult); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatal("principal query", res.StatusCode, body)
	}
	assertSelectedAcceptedRules(t, selectedResult.Result, accepted[0].Proposal.Payload)
	c, tokens = evidenceInfo(t, client, c.ID)
	exports := "/api/v1/evidence/cases/" + c.ID.String() + "/exports"
	res, c, body = evidencePost(t, client, exports, evidenceInput{Reason: "選択項目提出", Columns: []string{"connection"}}, c.ETag(), tokens[exports], domain.NewID().String())
	if res.StatusCode != 200 || len(c.Exports) != 1 {
		t.Fatal("export", res.StatusCode, body)
	}
	v := c.Exports[0]
	assertEvidenceExportHTTPDates(t, body, v)
	c, tokens = evidenceInfo(t, client, c.ID)
	download := "/api/v1/evidence/exports/" + v.ID.String() + "/download"
	res, c, zipBody := evidencePost(t, client, download, evidenceInput{CaseID: c.ID, Reason: "手動取得"}, c.ETag(), tokens[download], domain.NewID().String())
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "application/zip" {
		t.Fatal("download", res.StatusCode, zipBody)
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), 32)
	if e != nil {
		t.Fatal(e)
	}
	keyBytes := ed25519.NewKeyFromSeed(seed)
	defer clear(keyBytes)
	clear(seed)
	m, e := disclosure.VerifyZIP(bytes.NewReader([]byte(zipBody)), int64(len(zipBody)), keyBytes.Public().(ed25519.PublicKey))
	if e != nil || m.Count != 1 || len(m.Columns) != 1 || len(m.Sources) != 2 {
		t.Fatal("ZIP verify", m, e)
	}
	zr, err := zip.NewReader(bytes.NewReader([]byte(zipBody)), int64(len(zipBody)))
	if err != nil {
		t.Fatal(err)
	}
	foundHTTP := false
	for _, file := range zr.File {
		if file.Name == "records.csv" {
			reader, err := file.Open()
			if err != nil {
				t.Fatal(err)
			}
			payload, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Fatal(err)
			}
			foundHTTP = bytes.Contains(payload, []byte(optional.ID.String()))
			rows := evidenceCSVRows(t, payload)
			if len(rows) != 1 || rows[0]["result.response_event_ref"] != optional.ID.String() || rows[0]["identity.request_id"] != optional.Request.String() || rows[0]["result.response.finish_stage"] != "handler_return" || rows[0]["time.response_finished_at_jst"] != time.Unix(0, int64(optional.Finished)).In(domain.JST).Format(time.RFC3339Nano) {
				t.Fatal("CSV response binding")
			}
			if bytes.Contains(payload, []byte("PRIVATE-POST-BODY")) || bytes.Contains(payload, []byte("payload_base64")) {
				t.Fatal("ZIP private projection")
			}
		}
	}
	if !foundHTTP {
		t.Fatal("HTTP copy not in ZIP")
	}
	c, tokens = evidenceInfo(t, client, m.Case)
	res, _, _ = evidencePost(t, client, download, evidenceInput{CaseID: c.ID, Reason: "再取得"}, c.ETag(), tokens[download], domain.NewID().String())
	if res.StatusCode != 410 {
		t.Fatal("one-time download", res.StatusCode)
	}
	if res, page := client.request("GET", "/evidence", "", nil); res.StatusCode != 200 || !strings.Contains(page, "案件保全中") || strings.Contains(page, "PRIVATE-POST-BODY") {
		t.Fatal("HTML", res.StatusCode, page)
	}
	client.server.Close()
	fs.Close()
	repo.Close()
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("restart", e)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login after restart")
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	release := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
	res, c, body = evidencePost(t, client, release, evidenceInput{Reason: "対応完了"}, c.ETag(), tokens[release], domain.NewID().String())
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "cases", c.ID.String(), "http")); !os.IsNotExist(err) {
		t.Fatal("HTTP copies not reclaimed", err)
	}
	if res.StatusCode != 200 || c.State != "closed" || c.HTTP.State != "removed" {
		t.Fatal("release", res.StatusCode, body)
	}
	// 元予約Sync前後・案件参照Sync前に別要求で取消しても、copyを作らず元予約も解除する。
	for _, beforeSync := range []bool{false, true} {
		list, _ = client.request("GET", "/api/v1/evidence/cases", "", nil)
		res, pending, body := evidencePost(t, client, create, input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
		if res.StatusCode != 200 {
			t.Fatal("cancel race case create", res.StatusCode, body)
		}
		pending, pendingTokens := evidenceInfo(t, client, pending.ID)
		pendingHold := "/api/v1/evidence/cases/" + pending.ID.String() + "/hold"
		res, pending, body = evidencePost(t, client, pendingHold, evidenceInput{Reason: "取消競合の対象保全"}, pending.ETag(), pendingTokens[pendingHold], domain.NewID().String())
		if res.StatusCode != 200 {
			t.Fatal("cancel race accepted hold", res.StatusCode, body)
		}
		pending, pendingTokens = evidenceInfo(t, client, pending.ID)
		pendingHTTP := "/api/v1/evidence/cases/" + pending.ID.String() + "/http-hold"
		entered, proceed := make(chan struct{}), make(chan struct{})
		repo.mu.Lock()
		cancelSource := repo.optionalStore
		hook := func() { close(entered); <-proceed }
		if beforeSync {
			repo.optionalHoldBeforeReserve = hook
		} else {
			repo.optionalHoldAfterReserve = hook
		}
		repo.mu.Unlock()
		// cookie mapは各request側で独立所有する。
		holdingClient := &adminClient{t: t, server: client.server, cookies: maps.Clone(client.cookies), origin: client.origin}
		pendingBefore := pending
		pendingCSRF := pendingTokens[pendingHTTP]
		completed := make(chan int, 1)
		go func() {
			response, _, _ := evidencePost(t, holdingClient, pendingHTTP, evidenceInput{Reason: "取消前のHTTP保全"}, pendingBefore.ETag(), pendingCSRF, domain.NewID().String())
			completed <- response.StatusCode
		}()
		<-entered
		pending, pendingTokens = evidenceInfo(t, client, pending.ID)
		pendingRelease := "/api/v1/evidence/cases/" + pending.ID.String() + "/release"
		res, pending, body = evidencePost(t, client, pendingRelease, evidenceInput{Reason: "元予約待ち中に取消"}, pending.ETag(), pendingTokens[pendingRelease], domain.NewID().String())
		close(proceed)
		status := <-completed
		repo.mu.Lock()
		repo.optionalHoldAfterReserve = nil
		repo.optionalHoldBeforeReserve = nil
		repo.mu.Unlock()
		if res.StatusCode != 200 || status == 200 || pending.State != "closed" {
			t.Fatal("cancel race", res.StatusCode, status, body)
		}
		lease, found, leaseErr := cancelSource.OptionalHoldReceipt(pending.ID)
		if leaseErr != nil || !found || lease.State != "released" {
			t.Fatal("canceled source lease still active", lease, found, leaseErr)
		}
		if _, statErr := os.Stat(filepath.Join(cfg.DataDir, "cases", pending.ID.String(), "http")); !os.IsNotExist(statErr) {
			t.Fatal("canceled HTTP copy created", statErr)
		}
	}
	if _, e = OpenPostingRepository(cfg, postcapture.Validate); e == nil {
		t.Fatal("check must honor repository lock")
	}
	repo.Close()
	if reopened, err := OpenPostingRepository(cfg, postcapture.Validate); err != nil {
		t.Fatal("post release integrity", err)
	} else {
		reopened.Close()
	}
}
