// 板閉鎖の認可・公開停止・保持期限・容量回収順位と再起動を実保存データで検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

func closureForm(t *testing.T, c *adminClient, id domain.ID) (string, url.Values) {
	t.Helper()
	path := "/boards/" + id.String() + "/close"
	res, body := c.request("GET", path, "", nil)
	if res.StatusCode != 200 {
		t.Fatal("closure form", res.StatusCode, body)
	}
	return path, pageFields(body)
}

func TestBoardClosureHTTPAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { _ = repo.Close() }()
	info, err := repo.CreateBoard(t.Context(), "closing", "閉鎖対象")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer form.Close()
	posted, err := sendForm(form, url.Values{"bbs": {"closing"}, "subject": {"保持する題名"}, "MESSAGE": {"保持する本文"}, "oimo_request_id": {"closure-initial-post"}})
	if err != nil || !posted.Accepted {
		t.Fatal(posted, err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path, fields := closureForm(t, c, info.ID)
	fields.Set("confirm_key", "closing")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, _ := c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 403 {
		t.Fatal("reauthentication", res.StatusCode)
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	metadataPath, metadata := metadataForm(t, c, info.ID)
	metadata.Set("key", "closed_new")
	renamed, renamedBody := c.request("POST", metadataPath, metadata.Encode(), headers)
	if renamed.StatusCode != 303 {
		t.Fatal("rename before closure", renamed.StatusCode, renamedBody)
	}
	_, fields = closureForm(t, c, info.ID)
	fields.Set("confirm_key", "wrong")
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 422 {
		t.Fatal("confirmation", res.StatusCode)
	}
	fields.Set("confirm_key", "closed_new")
	csrf, revision := fields.Get("csrf"), fields.Get("revision")
	fields.Set("csrf", "invalid")
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 403 {
		t.Fatal("closure CSRF", res.StatusCode)
	}
	fields.Set("csrf", csrf)
	fields.Set("revision", `"stale"`)
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 412 {
		t.Fatal("closure CAS", res.StatusCode)
	}
	fields.Set("revision", revision)
	res, body := c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("close", res.StatusCode, body)
	}
	res, _ = c.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("retry", res.StatusCode)
	}
	b := repo.posting[info.ID]
	if b.closedAt.Load() <= 0 || b.threads[posted.Key].Reclaimed() {
		t.Fatal("closure prematurely reclaimed body")
	}
	if _, rows, err := repo.webBoards(); err != nil || len(rows) != 0 {
		t.Fatal("public board list", rows, err)
	}
	res, body = c.request("GET", "/boards", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "閉鎖対象") || !strings.Contains(body, "閉鎖済み") {
		t.Fatal("admin list", res.StatusCode, body)
	}
	public, err := repo.ValidationHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"/closing/", "/closing/subject.txt", "/closing/SETTING.TXT", "/closed_new/", "/closed_new/subject.txt", "/closed_new/SETTING.TXT", fmt.Sprintf("/closing/dat/%d.dat", posted.Key), fmt.Sprintf("/test/read.cgi/closing/%d/", posted.Key), "/web/post?bbs=closing", "/web/post?bbs=closed_new", fmt.Sprintf("/closed_new/dat/%d.dat", posted.Key), fmt.Sprintf("/test/read.cgi/closed_new/%d/", posted.Key)} {
		w := httptest.NewRecorder()
		public.Handler.ServeHTTP(w, webReadTestRequest("GET", cfg.Public.BaseURL+route, nil))
		if w.Code != 410 || strings.Contains(w.Body.String(), "保持する本文") {
			t.Fatal(route, w.Code, w.Body.String())
		}
	}
	reply, err := sendForm(form, url.Values{"bbs": {"closing"}, "key": {fmt.Sprint(posted.Key)}, "MESSAGE": {"拒否される返信"}, "oimo_request_id": {"closure-reply-post"}})
	if err != nil || reply.Accepted {
		t.Fatal("closed reply", reply, err)
	}
	if snapshot, err := repo.Thread(t.Context(), info.ID, posted.Key); err != nil || snapshot != nil {
		t.Fatal("internal public snapshot", err)
	}
	if _, err := repo.CreateBoard(t.Context(), "closing", "別の板"); err == nil {
		t.Fatal("closed key reused")
	}
	form.Close()
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	if repo.posting[info.ID].closedAt.Load() <= 0 {
		t.Fatal("closure lost")
	}
	if snapshot, err := repo.Thread(t.Context(), info.ID, posted.Key); err != nil || snapshot != nil {
		t.Fatal("closed board revived", err)
	}
	boards, err := repo.Boards()
	if err != nil || len(boards) != 1 || boards[0].Status != "closed" {
		t.Fatal("closed CLI status", boards, err)
	}
	verifyRenamedBoardBackup(t, repo, cfg)
}

func TestClosedBoardPressureBeforeActiveAndWithoutIdleWait(t *testing.T) {
	_, repo, activeID, activeKey := pressureRepositoryFixture(t)
	closed, err := repo.CreateBoard(t.Context(), "closed", "閉鎖板")
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := store.ReadFrame(bytes.NewReader(persistentFrame(t)))
	if err != nil {
		t.Fatal(err)
	}
	op, err := domain.ParseOperation(frame.Records[0].JSON)
	if err != nil {
		t.Fatal(err)
	}
	var create domain.Create
	if err := json.Unmarshal(op.Payload, &create); err != nil {
		t.Fatal(err)
	}
	create.Policy.Pinned = true
	op.Payload, _ = json.Marshal(create)
	frame.Records[0].JSON, _ = json.Marshal(op)
	raw, err := store.EncodeFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	result := repo.Post(t.Context(), closed.ID, 0, raw, []byte(`{"fixture":true}`))
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path, fields := closureForm(t, c, closed.ID)
	fields.Set("confirm_key", "closed")
	res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	repo.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: 10 << 30}, nil
	}
	for range 5 {
		if err := repo.SweepStoragePressure(t.Context()); err != nil {
			t.Fatal(err)
		}
		if repo.posting[activeID].threads[activeKey].Reclaimed() {
			t.Fatal("active board reclaimed before closed board originals")
		}
		if repo.StoragePressure().RemovedOriginals == 2 {
			break
		}
	}
	if !repo.posting[closed.ID].threads[result.ThreadKey].Reclaimed() || repo.StoragePressure().RemovedOriginals != 2 {
		t.Fatal(repo.StoragePressure())
	}
}

func TestBoardClosureDeadline(t *testing.T) {
	at := time.Date(2026, 8, 31, 12, 0, 0, 0, domain.JST)
	want := time.Date(2027, 2, 28, 12, 0, 0, 0, domain.JST)
	if got := boardClosureDeadline(domain.Time(at.UnixNano())); got != domain.Time(want.UnixNano()) {
		t.Fatal(got)
	}
}

// TestClosedBoardMonthEndDeadline は元期限が月末丸めで遅くなる場合も閉鎖期限で回収する。
func TestClosedBoardMonthEndDeadline(t *testing.T) {
	cfg, repo := adminFixture(t)
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postingCaptureFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err := repo.EnablePublicBodyReclamation(t.Context()); err != nil {
		t.Fatal(err)
	}
	info, err := repo.CreateBoard(t.Context(), "monthend", "月末閉鎖")
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[info.ID]
	b.expiryCancel()
	<-b.expiryDone
	postedAt := time.Date(2025, 8, 30, 23, 0, 0, 0, domain.JST)
	closedAt := time.Date(2025, 8, 31, 12, 0, 0, 0, domain.JST)
	deadline := domain.SixMonths(closedAt)
	value, err := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return postedAt }
		return b.post(0, persistentFrameAt(t, postedAt), []byte(`{"fixture":true}`)), nil
	})
	if err != nil || value.(RepositoryPostingResult).Status != store.Durable {
		t.Fatal(value, err)
	}
	key := value.(RepositoryPostingResult).ThreadKey
	_, err = b.worker.Submit(t.Context(), func() (any, error) { b.clock = func() time.Time { return closedAt }; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path, fields := closureForm(t, c, info.ID)
	fields.Set("confirm_key", "monthend")
	res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return deadline.Add(-time.Nanosecond) }
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sweep := func(at time.Time) int {
		t.Helper()
		repo.optionalHoldLifecycleMu.Lock()
		defer repo.optionalHoldLifecycleMu.Unlock()
		repo.mu.Lock()
		defer repo.mu.Unlock()
		n, err := repo.sweepClosedBoardOriginalsLocked(t.Context(), at)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	for range 4 {
		if n := sweep(deadline.Add(-time.Nanosecond)); n != 0 {
			t.Fatal("removed before closure deadline", n)
		}
	}
	if b.threads[key].Reclaimed() {
		t.Fatal("body removed before deadline")
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) { b.clock = func() time.Time { return deadline }; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	removed := 0
	for range 8 {
		removed += sweep(deadline)
	}
	if !b.threads[key].Reclaimed() || removed != 2 {
		t.Fatal("closure deadline not enforced", removed)
	}
	_, err = b.worker.Submit(t.Context(), func() (any, error) { b.clock = time.Now; return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPostingRepository(cfg, postingCaptureFixture)
	if err != nil {
		t.Fatal("deadline recovery", err)
	}
	defer reopened.Close()
}

// TestClosedBoardPressureIncludesHiddenOriginals は本文回収済み原本の早期削除と署名付き復旧を検証する。
func TestClosedBoardPressureIncludesHiddenOriginals(t *testing.T) {
	cfg, repo, id, key := pressureRepositoryFixture(t)
	b := repo.posting[id]
	_, err := b.worker.Submit(t.Context(), func() (any, error) {
		b.clock = func() time.Time { return time.Now().Add(-25 * time.Hour) }
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hideBodyFixture(t, repo, id, key)
	_, err = b.worker.Submit(t.Context(), func() (any, error) { b.clock = time.Now; return nil, b.cleanPublicBodies(1) })
	if err != nil || !b.threads[key].Reclaimed() {
		t.Fatal("hidden body", err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path, fields := closureForm(t, c, id)
	fields.Set("confirm_key", b.boardKey())
	res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	repo.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 100 << 30, Available: 10 << 30}, nil
	}
	for range 6 {
		if err := repo.SweepStoragePressure(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if repo.StoragePressure().RemovedOriginals != 2 {
		t.Fatal(repo.StoragePressure())
	}
	if _, ok := b.deletions[key].State().Rows["reclamation:closed_pressure"]; !ok {
		t.Fatal("signed closed pressure permission missing")
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPostingRepository(cfg, postingCaptureFixture)
	if err != nil {
		t.Fatal("closed hidden restart", err)
	}
	defer reopened.Close()
	if _, err := reopened.rateHistory(); err != nil {
		t.Fatal("retired rate recovery", err)
	}
}

// TestClosedBoardExpiryWithGlobalGCDisabled は通常期限の本文・原本回収を既存の時計で検証する。
func TestClosedBoardExpiryWithGlobalGCDisabled(t *testing.T) {
	cfg, repo, id, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path, fields := closureForm(t, c, id)
	fields.Set("confirm_key", repo.posting[id].boardKey())
	res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	if err := repo.DisableRequiredOriginalReclamation(t.Context()); err != nil {
		t.Fatal(err)
	}
	removed := 0
	for range 8 {
		n, err := repo.SweepRequiredOriginals(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		removed += n
	}
	if removed != 2 {
		t.Fatal("expired closed originals retained", removed)
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "boards", id.String(), "threads", fmt.Sprint(key))); !os.IsNotExist(err) {
		t.Fatal("body remains", err)
	}
}

// TestBoardClosureBrowser は閉鎖確認・再認証・閲覧停止と明暗両テーマの実画面を確認する。
func TestBoardClosureBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-board-closure-browser.mjs")
}

// TestBoardClosureStopsOnlySelectedStreams は本文と一覧の旧送信を止め、他板の送信を継続する。
func TestBoardClosureStopsOnlySelectedStreams(t *testing.T) {
	_, repo, closingID, closingKey := pressureRepositoryFixture(t)
	other, err := repo.CreateBoard(t.Context(), "continuing", "公開を続ける板")
	if err != nil {
		t.Fatal(err)
	}
	post := repo.Post(t.Context(), other.ID, 0, persistentFrame(t), []byte(`{"fixture":true}`))
	if post.Status != store.Durable {
		t.Fatal(post)
	}
	writers := []*publicResponse{}
	for _, target := range []struct {
		id  domain.ID
		key uint64
	}{{closingID, closingKey}, {other.ID, post.ThreadKey}} {
		snapshot, err := repo.Thread(t.Context(), target.id, target.key)
		if err != nil || snapshot == nil {
			t.Fatal(snapshot, err)
		}
		writer, err := publicWriter(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil), snapshot, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		writers = append(writers, writer)
	}
	menu, denied := repo.readingGate(httptest.NewRecorder(), webReadTestRequest("GET", "/bbsmenu.html", nil), "site")
	if denied {
		t.Fatal("menu denied before closure")
	}
	otherResponse, denied := repo.readingGate(httptest.NewRecorder(), webReadTestRequest("GET", "/continuing/subject.txt", nil), "site")
	if denied {
		t.Fatal("other board denied before closure")
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	path, fields := closureForm(t, c, closingID)
	fields.Set("confirm_key", repo.posting[closingID].boardKey())
	res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	if err := writers[0].check(); err == nil {
		t.Fatal("closed board stream continued")
	}
	if err := writers[1].check(); err != nil {
		t.Fatal("other board stream interrupted", err)
	}
	if err := menu.(*readingResponse).check(); err == nil {
		t.Fatal("stale menu continued")
	}
	if err := otherResponse.(*readingResponse).check(); err != nil {
		t.Fatal("unrelated response interrupted", err)
	}
}
