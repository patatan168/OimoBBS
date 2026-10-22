// 管理HTMLから一件の掃除を再試行し、容量失敗・CSRF・CASと対象外の保存不変を検査する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestAdminCleanupRetryHTTP(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "retry", "再試行")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	var paths []string
	var ids []domain.ID
	var keys []uint64
	for i := range 2 {
		result, err := sendForm(form, url.Values{"bbs": {"retry"}, "subject": {fmt.Sprintf("掃除%d", i)}, "MESSAGE": {"旧保存本文"}, "oimo_request_id": {fmt.Sprintf("retry-create-%04d", i)}})
		if err != nil || !result.Accepted {
			t.Fatal(result, err)
		}
		path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, result.Key)
		res, _ := c.request("GET", path, "", nil)
		raw, _ := json.Marshal(AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}})
		res, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {fmt.Sprintf("retry-redact-%04d", i)}})
		var saved struct {
			Data struct {
				ID domain.ID `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &saved); err != nil || res.StatusCode != 200 || saved.Data.ID == (domain.ID{}) {
			t.Fatal(res.StatusCode, body, err)
		}
		paths = append(paths, strings.TrimPrefix(path, "/api/v1"))
		ids = append(ids, saved.Data.ID)
		keys = append(keys, result.Key)
	}
	b := repo.posting[board.ID]
	otherSeq := b.deletions[keys[1]].State().Seq
	_, body := c.request("GET", paths[0], "", nil)
	allFields := pageFields(body)
	fields := url.Values{}
	for _, key := range []string{"csrf", "revision", "cleanup_id"} {
		fields.Set(key, allFields.Get(key))
	}
	if !strings.Contains(body, "この削除の保存掃除を再試行") || fields.Get("cleanup_id") != ids[0].String() {
		t.Fatal(body)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		b.reserveDeletionPack = func() (func(), error) { return nil, app.ErrPackCapacity }
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	res, _ := c.request("POST", paths[0]+"/cleanup", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 503 {
		t.Fatal("capacity falsely completed", res.StatusCode)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) { b.reserveDeletionPack = nil; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	bad := url.Values{}
	for k, v := range fields {
		bad[k] = append([]string{}, v...)
	}
	bad.Set("csrf", "invalid")
	res, _ = c.request("POST", paths[0]+"/cleanup", bad.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 403 {
		t.Fatal("CSRF bypass", res.StatusCode)
	}
	bad.Set("csrf", fields.Get("csrf"))
	bad.Set("revision", "stale")
	res, _ = c.request("POST", paths[0]+"/cleanup", bad.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 412 {
		t.Fatal("CAS bypass", res.StatusCode)
	}
	bad.Set("revision", fields.Get("revision"))
	bad.Set("cleanup_id", ids[1].String())
	res, _ = c.request("POST", paths[0]+"/cleanup", bad.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 404 {
		t.Fatal("other thread deletion accepted", res.StatusCode)
	}
	for range 2 {
		res, body = c.request("POST", paths[0]+"/cleanup", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != 303 {
			t.Fatal(res.StatusCode, body)
		}
	}
	res, body = c.request("GET", "/api/v1"+paths[0], "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `"state":"complete"`) {
		t.Fatal(res.StatusCode, body)
	}
	if b.deletions[keys[1]].State().Seq != otherSeq {
		t.Fatal("other thread was cleaned")
	}
}

func TestAdminCleanupViewerDenied(t *testing.T) {
	cfg, repo := adminFixture(t)
	board, err := repo.CreateBoard(t.Context(), "view", "閲覧")
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := repo.CreateAdministrator("cleanup.viewer", "閲覧担当", adminTestSecret, AdministratorAccess{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if _, e := repo.AdminHTTPServer(); e != nil {
		t.Fatal(e)
	}
	_, session, sessionErr := repo.adminAuth.Create(viewer.ID, viewer.Generation, time.Now())
	if sessionErr != nil {
		t.Fatal(sessionErr)
	}
	err = repo.retryRedactionCleanup(t.Context(), session, board.ID, 1, domain.NewID(), "")
	var failure *adminFailure
	if !errors.As(err, &failure) || failure.status != 403 {
		t.Fatal("viewer was not rejected before target lookup", err)
	}
}
