// 管理APIでの保存から投稿上限・終了レス・再起動までを検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
)

func TestThreadSettingsPostingAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + info.ID.String() + "/thread-settings"
	res, body := client.request("GET", path, "", nil)
	var initial struct{ Data AdminThreadSettings }
	if e = json.Unmarshal([]byte(body), &initial); e != nil || res.StatusCode != 200 {
		t.Fatal(body, e)
	}
	edit := initial.Data.Settings
	if edit.PostLimit != 1000 || !edit.First.Enabled || edit.Second.Enabled {
		t.Fatal("defaults", edit)
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer func() { form.Close() }()
	old, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"old"}, "MESSAGE": {"old"}})
	if e != nil || !old.Accepted {
		t.Fatal(old, e)
	}
	pendingFields := url.Values{"bbs": {"news"}, "subject": {"new"}, "MESSAGE": {"new"}, "oimo_request_id": {"thread-settings-create-01"}}
	pending, e := sendFormOnce(form, pendingFields, "")
	if e != nil || pending.Confirmation == nil {
		t.Fatal(pending, e)
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"thread-settings-save-001"}}
	edit.PostLimit = 2
	edit.First = EndingSettings{true, "End <one>", "sage", "first <b>\nsecond"}
	edit.Second = EndingSettings{true, "End two", "end@example.test", "finished"}
	raw, _ := json.Marshal(edit)
	res, body = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	saved := res.Header.Get("ETag")
	changed, e := sendFormOnce(form, pendingFields, pending.Confirmation.Token)
	if e != nil || !changed.Accepted || changed.Confirmation != nil {
		t.Fatal("settings update repeated consent", changed, e)
	}
	fresh, e := sendForm(form, pendingFields)
	if e != nil || !fresh.Accepted {
		t.Fatal(fresh, e)
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(fresh.Key)}, "MESSAGE": {"last"}, "oimo_request_id": {"thread-settings-reply-001"}}
	last, e := sendForm(form, reply)
	if e != nil || !last.Accepted || last.Number != 2 {
		t.Fatal(last, e)
	}
	duplicate, e := sendForm(form, reply)
	if e != nil || !duplicate.Duplicate {
		t.Fatal(duplicate, e)
	}
	snapshot, e := repo.Thread(context.Background(), info.ID, fresh.Key)
	if e != nil || snapshot.CanReply || snapshot.PostCount != 4 {
		t.Fatal("closure", snapshot, e)
	}
	dat := string(snapshot.DAT)
	if !strings.Contains(dat, "End &lt;one&gt;<>sage<>") || !strings.Contains(dat, "first &lt;b&gt;") || !strings.Contains(dat, "End two<>end@example.test<>") {
		t.Fatal("ending fields", dat)
	}
	oldReply, e := sendForm(form, url.Values{"bbs": {"news"}, "key": {fmt.Sprint(old.Key)}, "MESSAGE": {"still active"}})
	if e != nil || !oldReply.Accepted {
		t.Fatal(oldReply, e)
	}
	snapshot, e = repo.Thread(context.Background(), info.ID, old.Key)
	if e != nil || !snapshot.CanReply || snapshot.PostCount != 2 {
		t.Fatal("existing limit changed", snapshot, e)
	}
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != saved {
		t.Fatal("retry")
	}
	conflicting := edit
	conflicting.PostLimit = 3
	other, _ := json.Marshal(conflicting)
	res, _ = client.request("PATCH", path, string(other), headers)
	if res.StatusCode != 409 {
		t.Fatal("request conflict", res.StatusCode)
	}
	headers.Set("Idempotency-Key", "thread-settings-save-002")
	res, _ = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 412 {
		t.Fatal("revision conflict", res.StatusCode)
	}
	headers.Set("If-Match", saved)
	for _, limit := range []uint32{0, 10001} {
		invalid := edit
		invalid.PostLimit = limit
		b, _ := json.Marshal(invalid)
		res, _ = client.request("PATCH", path, string(b), headers)
		if res.StatusCode != 422 {
			t.Fatal("limit", res.StatusCode)
		}
	}
	badHeaders := headers.Clone()
	badHeaders.Del("X-Csrf-Token")
	res, _ = client.request("PATCH", path, string(raw), badHeaders)
	if res.StatusCode != 403 {
		t.Fatal("csrf", res.StatusCode)
	}
	form.Close()
	client.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reopen", e)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	res, body = client.request("GET", path, "", nil)
	var recovered struct{ Data AdminThreadSettings }
	if e = json.Unmarshal([]byte(body), &recovered); e != nil || recovered.Data.Settings != edit || res.Header.Get("ETag") != saved {
		t.Fatal("recovery", body, e)
	}
	headers.Set("If-Match", initial.Data.ETag())
	headers.Set("Idempotency-Key", "thread-settings-save-001")
	headers.Set("X-Csrf-Token", res.Header.Get("X-CSRF-Token"))
	res, body = client.request("PATCH", path, string(raw), headers)
	if res.StatusCode != 200 || res.Header.Get("ETag") != saved {
		t.Fatal("receipt recovery", body)
	}
	snapshot, e = repo.Thread(context.Background(), info.ID, fresh.Key)
	if e != nil || string(snapshot.DAT) != dat || snapshot.CanReply {
		t.Fatal("thread recovery", e)
	}
	// HTMLから両方を無効化し、上限1でも追加レスなしで終了する。
	fields := threadFields(edit)
	fields.Set("user_post_limit", "1")
	fields.Set("ending_1_enabled", "false")
	fields.Set("ending_2_enabled", "false")
	fields.Set("revision", saved)
	fields.Set("request_id", "thread-settings-form-001")
	fields.Set("csrf", headers.Get("X-CSRF-Token"))
	action := "/boards/" + info.ID.String() + "/thread-settings"
	res, body = client.request("POST", action, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("form save", res.StatusCode, body)
	}
	res, body = client.request("GET", action, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "End &lt;one&gt;") {
		t.Fatal("form escaping", res.StatusCode)
	}
	form = formServer(t, repo, siteID(repo.site.State()), info.ID)
	single, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"single"}, "MESSAGE": {"only"}})
	if e != nil || !single.Accepted {
		t.Fatal(single, e)
	}
	snapshot, e = repo.Thread(context.Background(), info.ID, single.Key)
	if e != nil || snapshot.CanReply || snapshot.PostCount != 1 {
		t.Fatal("disabled endings", snapshot, e)
	}
}
