// 実管理HTTPから延長intent/元lease/期限確定と再送、コピー再開、再起動を検査する。
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"oimobbs/internal/platform"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestAdminEvidencePendingHTTPHoldExtension(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial_reference", true: "bound_reference"}[bound], func(t *testing.T) {
			cfg, r, c, _, _ := optionalHeldCaseProductFixtureMode(t, bound)
			if _, e := r.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
				t.Fatal(e)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			var e error
			r, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { r.Close() })
			client := newAdminClient(t, r)
			t.Cleanup(client.server.Close)
			if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
				t.Fatal("login/reauth")
			}
			current, tokens := evidenceInfo(t, client, c.ID)
			etag := current.ETag()
			target := current.Until + domain.Time(24*time.Hour)
			input := evidenceInput{Reason: "原本保全期間の延長", Until: target}
			response, extended, body := evidencePost(t, client, "/api/v1/evidence/cases/"+c.ID.String()+"/extend", input, etag, tokens["/api/v1/evidence/cases/"+c.ID.String()+"/extend"], "http-extension-1")
			if response.StatusCode != http.StatusOK || extended.Extension == nil || extended.Extension.State != "complete" || extended.Until != target {
				t.Fatal(response.StatusCode, body)
			}
			receipt, found, e := r.optionalStore.OptionalHoldReceipt(c.ID)
			if e != nil || !found || receipt.Binding.Until != target || receipt.SHA != extended.HTTP.Reservation.SHA {
				t.Fatal(receipt, e)
			}
			var site siteState
			if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != 44 {
				t.Fatal("reader not activated before intent")
			}
			_, tokens = evidenceInfo(t, client, c.ID)
			response, replay, body := evidencePost(t, client, "/api/v1/evidence/cases/"+c.ID.String()+"/extend", input, etag, tokens["/api/v1/evidence/cases/"+c.ID.String()+"/extend"], "http-extension-1")
			if response.StatusCode != http.StatusOK || replay.ETag() != extended.ETag() {
				t.Fatal("request replay", response.StatusCode, body)
			}
			_, tokens = evidenceInfo(t, client, c.ID)
			response, copied, body := evidencePost(t, client, "/api/v1/evidence/cases/"+c.ID.String()+"/http-hold", evidenceInput{Reason: "延長済み原本を保全"}, extended.ETag(), tokens["/api/v1/evidence/cases/"+c.ID.String()+"/http-hold"], "http-extension-copy")
			if response.StatusCode != http.StatusOK || copied.HTTP.State != "active" || copied.HTTP.Released == nil {
				t.Fatal("copy/release", response.StatusCode, body)
			}
			if copied.Extension.Confirmed.SHA != extended.Extension.Confirmed.SHA {
				t.Fatal("historical confirmation replaced")
			}
			client.server.Close()
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("reader44 restart", e)
			}
			defer reopened.Close()
			reopened.mu.Lock()
			after, e := reopened.evidenceCases.Get(c.ID)
			reopened.mu.Unlock()
			if e != nil || after.Until != target || after.HTTP.Released == nil {
				t.Fatal(after, e)
			}
			if e = reopened.reconcileOptionalRetention(context.Background()); e != nil {
				t.Fatal("idempotent maintenance", e)
			}
		})
	}
}

// 元Sync前/直後の両停止点から、実Repository起動だけで延長確定を再開する。
func TestPendingExtensionStartupAndPeriodicRecovery(t *testing.T) {
	for _, advanced := range []bool{false, true} {
		t.Run(map[bool]string{false: "before_source_sync", true: "after_source_sync"}[advanced], func(t *testing.T) {
			cfg, r, c, _, _ := optionalHeldCaseProductFixture(t)
			r.mu.Lock()
			e := r.enableOptionalExtensionReaderLocked()
			if e == nil {
				c, e = r.evidenceCases.PrepareExtension(c.ID, c.Creator, c.ETag(), "restart-extension", "延長", c.Until+domain.Time(24*time.Hour), time.Now())
			}
			r.mu.Unlock()
			if e != nil {
				t.Fatal(e)
			}
			target := c.Extension.Until
			if advanced {
				b := c.Extension.Original.Binding
				b.Revision = c.Extension.Revision
				b.Until = target
				if _, e = r.optionalStore.RenewOptionalHold(context.Background(), c.Extension.Original, b, c.Extension.Requested, time.Now()); e != nil {
					t.Fatal(e)
				}
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			r, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer r.Close()
			r.mu.Lock()
			completed, e := r.evidenceCases.Get(c.ID)
			r.mu.Unlock()
			if e != nil || completed.Extension.State != "complete" || completed.Until != target {
				t.Fatal("startup did not complete intent", completed, e)
			}
			receipt, found, e := r.optionalStore.OptionalHoldReceipt(c.ID)
			if e != nil || !found || receipt.SHA != completed.HTTP.Reservation.SHA {
				t.Fatal(receipt, e)
			}
			if e = r.reconcileOptionalRetention(context.Background()); e != nil {
				t.Fatal(e)
			}
			r.mu.Lock()
			same, e := r.evidenceCases.Get(c.ID)
			r.mu.Unlock()
			after, _, ownerError := r.optionalStore.OptionalHoldReceipt(c.ID)
			if e != nil || ownerError != nil || same.ETag() != completed.ETag() || after.SHA != receipt.SHA {
				t.Fatal("periodic repeated completed update", same, e, ownerError)
			}
		})
	}
}

func TestPendingExtensionPeriodicCompletesAfterCapacityRecovery(t *testing.T) {
	_, r, c, _, _ := optionalHeldCaseProductFixture(t)
	r.mu.Lock()
	e := r.enableOptionalExtensionReaderLocked()
	if e == nil {
		c, e = r.evidenceCases.PrepareExtension(c.ID, c.Creator, c.ETag(), "periodic-extension", "延長", c.Until+domain.Time(24*time.Hour), time.Now())
	}
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}

	original, _, e := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e != nil {
		t.Fatal(e)
	}
	r.packResourcesMu.Lock()
	probe := r.packSpace
	r.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: (1 << 30) + postingReservationBytes}, nil
	}
	r.packResourcesMu.Unlock()
	e = r.reconcileOptionalRetention(context.Background())
	r.packResourcesMu.Lock()
	reserved := r.postReserved
	r.packSpace = probe
	r.packResourcesMu.Unlock()
	if !errors.Is(e, ErrPostingCapacity) || reserved != 0 {
		t.Fatal("extension consumed last posting slot", e, reserved)
	}
	r.mu.Lock()
	unchanged, caseError := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	source, _, sourceError := r.optionalStore.OptionalHoldReceipt(c.ID)
	if caseError != nil || sourceError != nil || unchanged.ETag() != c.ETag() || source.SHA != original.SHA {
		t.Fatal("capacity rejection changed intent/lease", caseError, sourceError)
	}
	r.optionalCancel()
	<-r.optionalDone
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	done := make(chan struct{})
	snapshot := make(chan struct{})
	r.optionalCancel = cancel
	r.optionalDone = done
	r.optionalLossMu.Lock()
	r.optionalLossBeforeSnapshot = func() { close(snapshot) }
	r.optionalLossMu.Unlock()
	go r.runOptionalLogMaintenance(ctx, r.optionalStore, ticks, done)
	ticks <- time.Now()
	select {
	case <-snapshot:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("periodic recovery did not finish")
	}
	cancel()
	<-done
	r.optionalLossMu.Lock()
	r.optionalLossBeforeSnapshot = nil
	r.optionalLossMu.Unlock()

	r.mu.Lock()
	completed, e := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if e != nil || completed.Extension.State != "complete" {
		t.Fatal(completed, e)
	}
}

func TestAdminEvidenceExtensionCancelledAfterSourceSync(t *testing.T) {
	cfg, r, c, _, _ := optionalHeldCaseProductFixture(t)
	if _, e := r.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	client := newAdminClient(t, r)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	oldUntil := c.Until
	synced, resume := make(chan struct{}), make(chan struct{})
	r.mu.Lock()
	r.optionalExtensionAfterRenew = func() { close(synced); <-resume }
	r.mu.Unlock()
	responseDone := make(chan int, 1)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	// client.cookiesは要求中も変更されない。csrfと入力は開始前に固定する。
	csrf, etag, target := tokens[path], c.ETag(), c.Until+domain.Time(24*time.Hour)
	go func() {
		response, _, _ := evidencePost(t, client, path, evidenceInput{Reason: "取消競合の延長", Until: target}, etag, csrf, "extension-cancel-race")
		responseDone <- response.StatusCode
	}()
	select {
	case <-synced:
	case <-time.After(5 * time.Second):
		close(resume)
		t.Fatal("source sync not reached")
	}
	_, tokens = evidenceInfo(t, client, c.ID)
	cancelPath := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
	current, _ := evidenceInfo(t, client, c.ID)
	response, closed, body := evidencePost(t, client, cancelPath, evidenceInput{Reason: "延長確定前の取消"}, current.ETag(), tokens[cancelPath], "cancel-extension-before-confirmation")
	close(resume)
	if response.StatusCode != http.StatusOK || closed.State != "closed" || closed.HTTP.Released == nil || closed.Until != oldUntil {
		t.Fatal("cancel", response.StatusCode, body)
	}
	select {
	case status := <-responseDone:
		if status < 400 {
			t.Fatal("stale extension completed after cancel", status)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("extension did not return")
	}
	r.mu.Lock()
	r.optionalExtensionAfterRenew = nil
	latest, e := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	receipt, _, sourceError := r.optionalStore.OptionalHoldReceipt(c.ID)
	if e != nil || sourceError != nil || latest.State != "closed" || latest.Until != oldUntil || receipt.State != "released" || latest.HTTP.Released.SHA != receipt.SHA {
		t.Fatal(latest, e, receipt, sourceError)
	}
}
