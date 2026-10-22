// 実管理HTTPで必須元の未反映参照/延長/再送/固定copyと、元待ち後の再認可/取消を検証する。
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"strings"
	"sync"
	"testing"
	"time"
)

// requiredHTTPExtensionFixture は実投稿原本に未完了予約を置き、延長を実セッションで要求できるようにする。
func requiredHTTPExtensionFixture(t *testing.T, bound bool) (Config, *Repository, *adminClient, disclosure.Case) {
	t.Helper()
	cfg, r, client, c, _ := requiredHTTPFixture(t)
	if e := r.ensureRequiredHoldStorage(t.Context(), c.Scope.Board); e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	rows, e := r.collectEvidence(t.Context(), c.Scope)
	if e == nil {
		c, e = r.evidenceCases.PrepareHold(c.ID, c.Creator, c.ETag(), "extension-original-pin", "原本保全", rows, time.Now())
	}
	var binding app.RequiredHoldBinding
	if e == nil {
		binding, e = r.evidenceCases.RequiredReservationBinding(c, time.Now())
	}
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	b := r.posting[c.Scope.Board]
	value, e := b.worker.Submit(t.Context(), func() (any, error) {
		return b.requiredHolds.Reserve(binding, rows, b.journals, domain.Time(time.Now().UnixNano()))
	})
	if e != nil {
		t.Fatal(e)
	}
	if bound {
		r.mu.Lock()
		c, e = r.evidenceCases.BindRequiredReservation(c.ID, c.Creator, c.ETag(), value.(app.RequiredHoldReceipt), time.Now())
		r.mu.Unlock()
		if e != nil {
			t.Fatal(e)
		}
	}
	return cfg, r, client, c
}

func TestRequiredHTTPExtensionReplayCopyAndReopen(t *testing.T) {
	for _, bound := range []bool{false, true} {
		t.Run(map[bool]string{false: "unreflected_reference", true: "bound_reference"}[bound], func(t *testing.T) {
			cfg, r, client, c := requiredHTTPExtensionFixture(t, bound)
			original := requiredSourceReceipt(t, r, c)
			path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
			_, tokens := evidenceInfo(t, client, c.ID)
			etag := c.ETag()
			input := evidenceInput{Reason: "必須原本の延長", Until: c.Until + domain.Time(24*time.Hour)}
			res, extended, body := evidencePost(t, client, path, input, etag, tokens[path], "required-extension-http")
			if res.StatusCode != 200 || extended.RequiredExtension == nil || extended.RequiredExtension.State != "complete" || extended.Until != input.Until {
				t.Fatal(res.StatusCode, body)
			}
			if extended.Revision != c.Revision+2 || extended.RequiredExtension.Original.SHA != original.SHA {
				t.Fatal("unreflected source adopted in separate row")
			}
			if strings.Contains(body, "PRIVATE_REQUIRED_HTTP_BODY") {
				t.Fatal("extension response included original body")
			}
			var site siteState
			r.mu.Lock()
			e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site)
			r.mu.Unlock()
			if e != nil || site.MinimumReader != 47 {
				t.Fatal("reader not saved before intent", e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			_, tokens = evidenceInfo(t, client, c.ID)
			res, replay, body := evidencePost(t, client, path, input, etag, tokens[path], "required-extension-http")
			if res.StatusCode != 200 || replay.ETag() != extended.ETag() {
				t.Fatal("request replay", res.StatusCode, body)
			}
			assertRequiredStartupFilesEqual(t, before, requiredStartupFiles(t, cfg.DataDir))
			hold := "/api/v1/evidence/cases/" + c.ID.String() + "/hold"
			_, tokens = evidenceInfo(t, client, c.ID)
			res, copied, body := evidencePost(t, client, hold, evidenceInput{Reason: "延長済み原本の保全"}, extended.ETag(), tokens[hold], "required-extension-copy")
			if res.StatusCode != 200 || copied.State != "active" || copied.Required.Released == nil {
				t.Fatal("copy/release", res.StatusCode, body)
			}
			if copied.Required.Reservation.SHA != extended.RequiredExtension.Confirmed.SHA {
				t.Fatal("renewed reference replaced during copy")
			}
			client.server.Close()
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			reopened.mu.Lock()
			after, e := reopened.evidenceCases.Get(c.ID)
			reopened.mu.Unlock()
			if e != nil || after.Until != input.Until || after.Required.Released == nil {
				t.Fatal("reader47 restart", e)
			}
		})
	}
}

func TestRequiredHTTPExtensionStaleRequestDoesNotRaiseReader(t *testing.T) {
	_, r, client, c := requiredHTTPExtensionFixture(t, false)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	_, tokens := evidenceInfo(t, client, c.ID)
	res, _, body := evidencePost(t, client, path, evidenceInput{Reason: "延長", Until: c.Until + 1}, "stale", tokens[path], "required-extension-stale")
	if res.StatusCode != http.StatusPreconditionFailed {
		t.Fatal(res.StatusCode, body)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != 46 {
		t.Fatal("stale request raised reader", e)
	}
}

func TestRequiredHTTPExtensionRechecksActualPermissionAfterRenew(t *testing.T) {
	_, r, client, c := requiredHTTPExtensionFixture(t, true)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	_, tokens := evidenceInfo(t, client, c.ID)
	r.mu.Lock()
	r.requiredExtensionAfterRenew = func() {
		_, e := r.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true})
		if e != nil {
			t.Error(e)
		}
	}
	r.mu.Unlock()
	res, _, body := evidencePost(t, client, path, evidenceInput{Reason: "延長", Until: c.Until + domain.Time(time.Hour)}, c.ETag(), tokens[path], "required-extension-revoked")
	if res.StatusCode == 200 {
		t.Fatal("revoked session completed extension", body)
	}
	r.mu.Lock()
	r.requiredExtensionAfterRenew = nil
	current, e := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	if current.Until != c.Until || current.RequiredExtension.State != "pending" || current.Required.Released != nil {
		t.Fatal("revoked request published deadline or released legitimate lease")
	}
	if receipt := requiredSourceReceipt(t, r, current); receipt.State != "active" || receipt.Binding.Until <= c.Until {
		t.Fatal("legitimate renewed source not retained")
	}
}

func TestRequiredHTTPExtensionCancellationDuringRenew(t *testing.T) {
	_, r, client, c := requiredHTTPExtensionFixture(t, false)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	_, tokens := evidenceInfo(t, client, c.ID)
	entered, proceed := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(proceed) }) })
	r.mu.Lock()
	r.requiredExtensionAfterRenew = func() { close(entered); <-proceed }
	r.mu.Unlock()
	done := make(chan int, 1)
	go func() {
		res, _, _ := evidencePost(t, client, path, evidenceInput{Reason: "延長", Until: c.Until + domain.Time(time.Hour)}, c.ETag(), tokens[path], "required-extension-cancel")
		done <- res.StatusCode
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("renew wait not reached")
	}
	cancelClient := newAdminClient(t, r)
	defer cancelClient.server.Close()
	if cancelClient.login(adminTestSecret) != 303 || cancelClient.reauth(adminTestSecret) != 200 {
		t.Fatal("cancel authentication")
	}
	current, cancelTokens := evidenceInfo(t, cancelClient, c.ID)
	release := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
	res, closed, body := evidencePost(t, cancelClient, release, evidenceInput{Reason: "取消"}, current.ETag(), cancelTokens[release], "required-extension-release")
	unblock.Do(func() { close(proceed) })
	if res.StatusCode != 200 || closed.State != "closed" || closed.Required.Released == nil {
		t.Fatal("cancel source release", res.StatusCode, body)
	}
	select {
	case status := <-done:
		if status == 200 {
			t.Fatal("cancelled extension confirmed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("extension request did not finish")
	}
	r.mu.Lock()
	r.requiredExtensionAfterRenew = nil
	current, e := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if e != nil || current.State != "closed" || current.Until != c.Until {
		t.Fatal("cancel resurrected", e)
	}
}

func TestRequiredHTTPExtensionResumesOriginalRequestAfterContextCancellation(t *testing.T) {
	_, r, client, c := requiredHTTPExtensionFixture(t, false)
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
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	until := c.Until + domain.Time(time.Hour)
	etag := c.ETag()
	key := "required-extension-context-retry"
	request := httptest.NewRequest("POST", path, nil).WithContext(ctx)
	r.mu.Lock()
	r.requiredExtensionAfterRenew = cancel
	_, e = r.extendEvidenceCase(request, session, c, etag, key, "延長", until)
	r.requiredExtensionAfterRenew = nil
	current, getErr := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if !errors.Is(e, context.Canceled) || getErr != nil || current.RequiredExtension.State != "pending" || current.Until != c.Until {
		t.Fatal(e, getErr)
	}
	_, tokens := evidenceInfo(t, client, c.ID)
	res, extended, body := evidencePost(t, client, path, evidenceInput{Reason: "延長", Until: until}, etag, tokens[path], key)
	if res.StatusCode != 200 || extended.RequiredExtension.State != "complete" || extended.Until != until {
		t.Fatal("original old CAS/key retry", res.StatusCode, body)
	}
}

func TestRequiredHTTPExtensionRejectsKeyCollisionBeforeReaderChange(t *testing.T) {
	_, r, client, c := requiredHTTPExtensionFixture(t, false)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	_, tokens := evidenceInfo(t, client, c.ID)
	res, _, body := evidencePost(t, client, path, evidenceInput{Reason: "延長", Until: c.Until + domain.Time(time.Hour)}, c.ETag(), tokens[path], "extension-original-pin")
	if res.StatusCode != http.StatusConflict {
		t.Fatal(res.StatusCode, body)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != 46 {
		t.Fatal("key collision raised reader", e)
	}
}

func TestRequiredHTTPExtensionSecondApprovalAndOldReplay(t *testing.T) {
	_, r, client, c := requiredHTTPExtensionFixture(t, true)
	path := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	etag := c.ETag()
	first := evidenceInput{Reason: "最初の延長", Until: c.Until + domain.Time(time.Hour)}
	_, tokens := evidenceInfo(t, client, c.ID)
	res, one, body := evidencePost(t, client, path, first, etag, tokens[path], "required-extension-first")
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	_, tokens = evidenceInfo(t, client, c.ID)
	res, two, body := evidencePost(t, client, path, evidenceInput{Reason: "追加延長", Until: one.Until + domain.Time(time.Hour)}, one.ETag(), tokens[path], "required-extension-second")
	if res.StatusCode != 200 || two.RequiredExtension.Original.SHA != one.RequiredExtension.Confirmed.SHA {
		t.Fatal("second approval changed old CAS", res.StatusCode, body)
	}
	_, tokens = evidenceInfo(t, client, c.ID)
	res, _, body = evidencePost(t, client, path, first, etag, tokens[path], "required-extension-first")
	if res.StatusCode != http.StatusConflict {
		t.Fatal("old replay skipped subsequent approval", res.StatusCode, body)
	}
	r.mu.Lock()
	current, e := r.evidenceCases.Get(c.ID)
	r.mu.Unlock()
	if e != nil || current.ETag() != two.ETag() {
		t.Fatal("old replay changed current case", e)
	}
}
