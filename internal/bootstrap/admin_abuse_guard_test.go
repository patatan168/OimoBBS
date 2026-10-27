// 共通対策の実HTTP設定・投稿拒否・再送・再起動・snapshot・権限と厳密入力を検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func saveGuardSettings(t *testing.T, c *adminClient, v AbuseGuardSettings, key string) (*http.Response, AdminAbuseGuard) {
	t.Helper()
	res, body := c.request("GET", "/api/v1/abuse-guard", "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {key}}
	raw, _ := json.Marshal(v)
	res, body = c.request("PATCH", "/api/v1/abuse-guard", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save guard", res.StatusCode, body)
	}
	var result struct {
		Data AdminAbuseGuard `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatal(err)
	}
	retry, b := c.request("PATCH", "/api/v1/abuse-guard", string(raw), headers)
	if retry.StatusCode != 200 || retry.Header.Get("ETag") != res.Header.Get("ETag") {
		t.Fatal("retry", retry.StatusCode, b)
	}
	raw, _ = json.Marshal(defaultAbuseGuard())
	if !reflect.DeepEqual(v, defaultAbuseGuard()) {
		conflict, _ := c.request("PATCH", "/api/v1/abuse-guard", string(raw), headers)
		if conflict.StatusCode != 409 {
			t.Fatal("key conflict", conflict.StatusCode)
		}
	}
	return res, result.Data
}
func TestAbuseGuardHTTPPostingRestartAndSnapshot(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	a, err := repo.CreateBoard(t.Context(), "guardone", "対策一")
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.CreateBoard(t.Context(), "guardtwo", "対策二")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	res, _ := c.request("GET", "/abuse-guard", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("anonymous access")
	}
	c.login(adminTestSecret)
	v := defaultAbuseGuard()
	v.Similar.Mode = "reject"
	v.Similar.MatchPosts = 2
	v.Flood.Mode = "off"
	v.Rates.Enabled = false
	_, view := saveGuardSettings(t, c, v, "guard-first-save-0001")
	if !view.Configured || view.Revision == 0 {
		t.Fatal(view)
	}
	formA := formServer(t, repo, siteID(repo.site.State()), a.ID)
	defer func() { formA.Close() }()
	formB := formServer(t, repo, siteID(repo.site.State()), b.ID)
	defer func() { formB.Close() }()
	fields := url.Values{"bbs": {"guardone"}, "subject": {"試験"}, "MESSAGE": {"これが広告として繰り返す同じ内容の文章です。"}, "oimo_request_id": {"guard-post-first-0001"}}
	first, err := sendForm(formA, fields)
	if err != nil || !first.Accepted {
		t.Fatal("first", first, err)
	}
	fields.Set("oimo_request_id", "guard-post-second-0001")
	second, err := sendForm(formA, fields)
	if err != nil || !second.Accepted {
		t.Fatal("second", second, err)
	}
	fields.Set("bbs", "guardtwo")
	fields.Set("oimo_request_id", "guard-post-blocked-0001")
	blocked, err := sendForm(formB, fields)
	if err != nil || blocked.Accepted {
		t.Fatal("cross-board bypass", blocked, err)
	}
	// 判定条件を厳しくしても受理済みの再送は元結果に戻し、索引へ重複追加しない。
	v.Similar.MatchPosts = 1
	saveGuardSettings(t, c, v, "guard-stricter-save-0001")
	fields.Set("bbs", "guardone")
	fields.Set("oimo_request_id", "guard-post-first-0001")
	retry, err := sendForm(formA, fields)
	if err != nil || !retry.Accepted || !retry.Duplicate || retry.Key != first.Key {
		t.Fatal("retry rejected", retry, err)
	}
	repo.guard.mu.Lock()
	count := len(repo.guard.entries)
	repo.guard.mu.Unlock()
	if count != 2 {
		t.Fatal("retry or rejection counted", count)
	}
	_, page := c.request("GET", "/abuse-guard", "", nil)
	if !strings.Contains(page, "掲示板全体") || !strings.Contains(page, "類似本文の連投") || strings.Contains(page, "これが広告として") {
		t.Fatal("private-free admin page")
	}
	// 保存形式の独立snapshotでも共通設定と変更履歴が有効。
	state := repo.site.State()
	header := store.Header{Kind: 1, Owner: siteID(state), Generation: 2, BaseSeq: uint64(state.Seq)}
	raw, err := store.EncodeControlSnapshot(header, state, 6, snapshotSiteValue)
	if err != nil {
		t.Fatal("snapshot encode", err)
	}
	if _, err = store.DecodeControlSnapshot(raw, header, snapshotSiteValue); err != nil {
		t.Fatal("snapshot decode", err)
	}
	formA.Close()
	formB.Close()
	c.server.Close()
	if _, err = repo.EnableControlSnapshots(t.Context()); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(candidateParent(t), "guard-candidate")
	if _, err = repo.PrepareControlSnapshot(t.Context(), candidate, 6); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	if _, err = ActivateControlSnapshot(t.Context(), cfg, candidate, postcapture.Validate); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	c = newAdminClient(t, repo)
	c.login(adminTestSecret)
	res, body := c.request("GET", "/api/v1/abuse-guard", "", nil)
	if res.StatusCode != 200 {
		t.Fatal(body)
	}
	var got struct {
		Data AdminAbuseGuard `json:"data"`
	}
	json.Unmarshal([]byte(body), &got)
	if !reflect.DeepEqual(got.Data.Settings, v) || !got.Data.Configured {
		t.Fatal("settings lost")
	}
	formB = formServer(t, repo, siteID(repo.site.State()), b.ID)
	fields.Set("bbs", "guardtwo")
	fields.Set("oimo_request_id", "guard-restart-reject-0001")
	blocked, err = sendForm(formB, fields)
	if err != nil || blocked.Accepted {
		t.Fatal("restart cleared similarity", blocked, err)
	}
	other, err := repo.CreateBoard(t.Context(), "guardnew", "新板")
	if err != nil {
		t.Fatal(err)
	}
	if repo.posting[other.ID].guard != repo.guard {
		t.Fatal("new board lacks common guard")
	}
}
func TestAbuseGuardHTTPRandomFloodAndBatch(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "flood", "埋め立て")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	v := defaultAbuseGuard()
	v.Similar.Mode = "off"
	v.Flood.Mode = "reject"
	v.Flood.ThreadPosts = 4
	v.Flood.SubjectPosts = 100
	v.Flood.ShareMinPosts = 100
	v.Rates.Enabled = false
	saveGuardSettings(t, c, v, "flood-policy-save-0001")
	server := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer server.Close()
	first, err := sendForm(server, url.Values{"bbs": {"flood"}, "subject": {"試験"}, "MESSAGE": {"通常の開始"}, "oimo_request_id": {"flood-create-0001"}})
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	// 同意済みの専ブラ返信を並列送信し、未確定バッチも上限へ数える。
	consent, err := sendFormOnce(server, url.Values{"bbs": {"flood"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"同意確認のみ"}}, "")
	if err != nil || consent.Confirmation == nil {
		t.Fatal(consent, err)
	}
	forms := make([]url.Values, 8)
	for i := range forms {
		forms[i] = url.Values{"bbs": {"flood"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {fmt.Sprintf("ランダム本文%d", i)}, "oimo_request_id": {fmt.Sprintf("flood-random-reply-%04d", i)}}
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	start := make(chan struct{})
	for i := range forms {
		wg.Go(func() {
			<-start
			r, err := sendFormOnce(server, forms[i], consent.Confirmation.Token)
			if err != nil {
				t.Error(err)
			}
			if r.Accepted {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		})
	}
	close(start)
	wg.Wait()
	if accepted != 3 {
		t.Fatal("batch flood limit", accepted)
	}
	snapshot, err := repo.Thread(t.Context(), board.ID, first.Key)
	if err != nil || snapshot.PostCount != 4 {
		t.Fatal("thread overfilled", snapshot, err)
	}
}
func TestAbuseGuardHTTPStrictInputAndHTML(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	res, body := c.request("GET", "/api/v1/abuse-guard", "", nil)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"guard-invalid-input-0001"}}
	raw, _ := json.Marshal(defaultAbuseGuard())
	base := string(raw)
	for _, bad := range []string{`{}`, strings.Replace(base, `"mode":"observe"`, `"mode":null`, 1), strings.Replace(base, `"mode":"observe"`, `"mode":"observe","mode":"reject"`, 1), strings.Replace(base, `"mode":"observe"`, `"mode":"observe","unknown":1`, 1)} {
		got, _ := c.request("PATCH", "/api/v1/abuse-guard", bad, headers)
		if got.StatusCode != 400 {
			t.Fatal("strict input", got.StatusCode, bad)
		}
	}
	badHeaders := headers.Clone()
	badHeaders.Set("X-CSRF-Token", "bad")
	got, _ := c.request("PATCH", "/api/v1/abuse-guard", base, badHeaders)
	if got.StatusCode != 403 {
		t.Fatal("CSRF")
	}
	got, body = c.request("GET", "/abuse-guard", "", nil)
	fields := guardFields(defaultAbuseGuard())
	hidden := pageFields(body)
	for _, name := range []string{"csrf", "revision", "request_id"} {
		fields.Set(name, hidden.Get(name))
	}
	fields.Set("similar_threshold", "101")
	fields.Set("similar_mode", "<script>")
	got, body = c.request("POST", "/abuse-guard", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if got.StatusCode != 422 || !strings.Contains(body, `value="101"`) || strings.Contains(body, "<script>入力") {
		t.Fatal("HTML input retention", got.StatusCode)
	}
	fields.Set("similar_threshold", "90")
	fields.Set("similar_mode", "observe")
	got, body = c.request("POST", "/abuse-guard", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if got.StatusCode != 303 {
		t.Fatal("HTML save", got.StatusCode, body)
	}
}
