// 実管理HTTPで元予約Sync待ち中の取消・権限変更と固定copy再開、耐久解除を確認する。
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"testing"
	"time"
)

func TestRequiredHTTPStaleRevisionDoesNotActivateStorage(t *testing.T) {
	_, r, client, c, tokens := requiredHTTPFixture(t)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
	res, _, body := evidencePost(t, client, path, evidenceInput{Reason: "保全"}, `"stale-case-revision"`, tokens[path], "required-stale-request")
	if res.StatusCode != http.StatusPreconditionFailed {
		t.Fatal(res.StatusCode, body)
	}
	r.mu.Lock()
	_, exists := r.site.State().Rows["required_holds:"+c.Scope.Board.String()]
	r.mu.Unlock()
	if exists {
		t.Fatal("stale request changed storage and backup boundary")
	}
}

func TestRequiredHTTPResumesDurablePinAfterContextCancellation(t *testing.T) {
	_, r, client, c, _ := requiredHTTPFixture(t)
	if e := r.ensureRequiredHoldStorage(t.Context(), c.Scope.Board); e != nil {
		t.Fatal(e)
	}
	manager := r.adminAuth
	r.mu.Lock()
	admins, e := r.administrators()
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	var generation domain.U64
	for _, a := range admins {
		if a.ID == c.Creator {
			generation = a.Generation
		}
	}
	cookie, session, e := manager.Create(c.Creator, generation, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	_, session, e = manager.MarkReauthenticated(cookie, session, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	etag, key := c.ETag(), "required-context-retry"
	r.mu.Lock()
	r.requiredHoldAfterReserve = cancel
	pending, e := r.holdRequiredEvidence(ctx, session, c, etag, key, "保全")
	r.requiredHoldAfterReserve = nil
	current, getErr := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if !errors.Is(e, context.Canceled) || getErr != nil || current.State != "preparing" || current.Required != nil {
		t.Fatal("cancelled request advanced copy", pending, e, getErr)
	}
	original := requiredSourceReceipt(t, r, current)
	if original.State != "active" {
		t.Fatal("request cancellation released legitimate pin")
	}
	current, tokens := evidenceInfo(t, client, c.ID)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
	res, completed, body := evidencePost(t, client, path, evidenceInput{Reason: "保全"}, etag, tokens[path], key)
	if res.StatusCode != 200 || completed.State != "active" || completed.Required == nil || completed.Required.Released == nil || completed.Required.Reservation.SHA != original.SHA {
		t.Fatal("durable reservation retry", res.StatusCode, body)
	}
}

func requiredHTTPFixture(t *testing.T) (Config, *Repository, *adminClient, disclosure.Case, map[string]string) {
	t.Helper()
	cfg, r, id := requiredHoldStorageFixture(t)
	if _, e := r.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	var reopenErr error
	r, reopenErr = OpenPostingRepository(cfg, postcapture.Validate)
	if reopenErr != nil {
		t.Fatal(reopenErr)
	}
	t.Cleanup(func() { r.Close() })
	client := newAdminClient(t, r)
	t.Cleanup(client.server.Close)
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	server := formServer(t, r, siteID(r.site.State()), id)
	posted, e := sendForm(server, url.Values{"bbs": {"requiredlog"}, "subject": {"必須HTTP保全"}, "MESSAGE": {"PRIVATE_REQUIRED_HTTP_BODY"}, "oimo_request_id": {"required-http-post"}})
	server.Close()
	if e != nil || !posted.Accepted {
		t.Fatal(posted, e)
	}
	now := time.Now()
	list, _ := client.request("GET", "/api/v1/evidence/cases", "", nil)
	res, c, body := evidencePost(t, client, "/api/v1/evidence/cases", evidenceInput{Number: "required-http", Reason: "保全", Until: domain.Time(now.Add(time.Hour).UnixNano()), Scope: disclosure.Scope{Board: id, Thread: domain.U64(posted.Key), From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano()), Records: []domain.ID{}}}, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), "required-http-create")
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	return cfg, r, client, c, tokens
}

func requiredSourceReceipt(t *testing.T, r *Repository, c disclosure.Case) app.RequiredHoldReceipt {
	t.Helper()
	b := r.posting[c.Scope.Board]
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		receipt, found, e := b.requiredHolds.Receipt(c.ID)
		if e == nil && !found {
			t.Error("required receipt missing")
		}
		return receipt, e
	})
	if e != nil {
		t.Fatal(e)
	}
	return value.(app.RequiredHoldReceipt)
}

func TestRequiredHTTPSourceWaitCancellation(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_sync", true: "after_sync"}[after], func(t *testing.T) {
			_, r, client, c, tokens := requiredHTTPFixture(t)
			entered, proceed := make(chan struct{}), make(chan struct{})
			hook := func() { close(entered); <-proceed }
			r.mu.Lock()
			if after {
				r.requiredHoldAfterReserve = hook
			} else {
				r.requiredHoldBeforeReserve = hook
			}
			r.mu.Unlock()
			path := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
			done := make(chan int, 1)
			go func() {
				res, _, _ := evidencePost(t, client, path, evidenceInput{Reason: "原本保全"}, c.ETag(), tokens[path], "required-cancel-hold")
				done <- res.StatusCode
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("source wait not reached")
			}
			// 元待ち中も管理要求が案件mutexを取得し、先行取消を署名できる。
			cancelClient := newAdminClient(t, r)
			defer cancelClient.server.Close()
			if cancelClient.login(adminTestSecret) != 303 || cancelClient.reauth(adminTestSecret) != 200 {
				t.Fatal("cancel authentication")
			}
			current, cancelTokens := evidenceInfo(t, cancelClient, c.ID)
			cancelPath := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
			res, closed, body := evidencePost(t, cancelClient, cancelPath, evidenceInput{Reason: "先行取消"}, current.ETag(), cancelTokens[cancelPath], "required-cancel-01")
			close(proceed)
			if res.StatusCode != 200 || closed.State != "closed" {
				t.Fatal(res.StatusCode, body)
			}
			select {
			case status := <-done:
				if status == 200 {
					t.Fatal("cancelled copy completed")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("hold did not finish")
			}
			current, _ = evidenceInfo(t, cancelClient, c.ID)
			receipt := requiredSourceReceipt(t, r, current)
			if receipt.State != "released" || current.Required == nil || current.Required.Released == nil || current.Required.Released.SHA != receipt.SHA {
				t.Fatal("cancelled source remained pinned", current, receipt)
			}
			if _, e := r.evidenceCases.Records(current, time.Now()); e == nil {
				t.Fatal("cancelled case disclosed")
			}
		})
	}
}

func TestRequiredHTTPRechecksPermissionAfterSourceSync(t *testing.T) {
	_, r, client, c, tokens := requiredHTTPFixture(t)
	r.mu.Lock()
	r.requiredHoldAfterReserve = func() {
		if _, e := r.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
			t.Error(e)
		}
	}
	r.mu.Unlock()
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
	res, _, body := evidencePost(t, client, path, evidenceInput{Reason: "保全"}, c.ETag(), tokens[path], "required-revoked-hold")
	if res.StatusCode == 200 {
		t.Fatal("revoked request completed", body)
	}
	r.mu.Lock()
	current, e := r.evidenceCases.Get(c.ID)
	r.requiredHoldAfterReserve = nil
	r.mu.Unlock()
	if e != nil || current.State != "preparing" || current.Required != nil {
		t.Fatal("copy or ref saved without current auth", current, e)
	}
	if receipt := requiredSourceReceipt(t, r, current); receipt.State != "active" {
		t.Fatal("permission loss discarded valid reservation", receipt)
	}
}

func TestRequiredHTTPCopyReplayAndRestart(t *testing.T) {
	cfg, r, client, c, tokens := requiredHTTPFixture(t)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
	etag, key := c.ETag(), "required-success-hold"
	res, held, body := evidencePost(t, client, path, evidenceInput{Reason: "保全"}, etag, tokens[path], key)
	if res.StatusCode != http.StatusOK || held.State != "active" || held.Required == nil || held.Required.Released == nil {
		t.Fatal(res.StatusCode, body)
	}
	_, tokens = evidenceInfo(t, client, c.ID)
	res, replayed, body := evidencePost(t, client, path, evidenceInput{Reason: "保全"}, etag, tokens[path], key)
	if res.StatusCode != 200 || replayed.ETag() != held.ETag() {
		t.Fatal("hold replay", res.StatusCode, body)
	}
	client.server.Close()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := checkLockedPosting(cfg, false, true); e != nil {
		t.Fatal("read-only product check", e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("restart", e)
	}
	defer reopened.Close()
	reopened.mu.Lock()
	current, e := reopened.evidenceCases.Get(c.ID)
	if e == nil {
		e = reopened.reconcileTerminalRequiredHoldsLocked(context.Background())
	}
	reopened.mu.Unlock()
	if e != nil || current.ETag() != held.ETag() {
		t.Fatal("restart changed completed case", current, e)
	}
	records, e := reopened.evidenceCases.Records(current, time.Now())
	if e != nil || len(records) != 1 {
		t.Fatal("independent copy missing", e)
	}
}
