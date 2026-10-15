// 削除HTTPとHTMLの日付が保存値の同じ瞬間を示すことを確認する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
)

func TestAdminDeletionDates(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"日時"}, "MESSAGE": {"本文"}, "oimo_request_id": {"deletion-date-create-001"}})
	if err != nil || !created.Accepted {
		t.Fatal(err, created)
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, created.Key)
	res, _ := c.request("GET", path, "", nil)
	edit := AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: 1, Last: 1, Mode: "aboon"}}}
	raw, _ := json.Marshal(edit)
	res, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"deletion-date-request-001"}})
	var response struct {
		Data deletionHTTPView `json:"data"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &response) != nil {
		t.Fatal(res.StatusCode, body)
	}
	v := response.Data
	for _, date := range []struct {
		text string
		ns   int64
	}{{v.CreatedAt, int64(v.Created)}, {v.ExpiresAt, int64(v.Expires)}, {v.CleanupDueAt, int64(v.CleanupDue)}} {
		at, err := time.Parse(time.RFC3339Nano, date.text)
		if err != nil || at.UnixNano() != date.ns {
			t.Fatal("date mismatch", date, err)
		}
	}
	res, body = c.request("GET", path, "", nil)
	var listing struct {
		Data struct {
			Deletions []deletionHTTPView     `json:"deletions"`
			Tasks     []deletionTaskHTTPView `json:"copy_tasks"`
		} `json:"data"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &listing) != nil || len(listing.Data.Deletions) != 1 || listing.Data.Deletions[0].CleanupDueAt != v.CleanupDueAt {
		t.Fatal(res.StatusCode, body)
	}
	res, body = c.request("GET", strings.TrimPrefix(path, "/api/v1"), "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, v.CleanupDueAt) || strings.Contains(body, "掃除予定（ns）") {
		t.Fatal(res.StatusCode, body)
	}
	// 未完了のコピーはnull、完了日時は元のnsと同じ瞬間を返す。
	views := deletionTaskHTTPValues([]DeletionCopyTask{{Verified: &v.Created}, {}})
	if views[0].VerifiedAt == nil || *views[0].VerifiedAt != v.CreatedAt || views[1].VerifiedAt != nil {
		t.Fatal(views)
	}
}

func TestAdminDeletionHistoryPages(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"履歴"}, "MESSAGE": {"本文"}, "oimo_request_id": {"deletion-pages-create-001"}})
	if err != nil || !created.Accepted {
		t.Fatal(err, created)
	}
	for i := range 2 {
		reply, err := sendForm(form, url.Values{"bbs": {"news"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"返信"}, "oimo_request_id": {fmt.Sprintf("deletion-pages-reply-%04d", i)}})
		if err != nil || !reply.Accepted {
			t.Fatal(err, reply)
		}
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, created.Key)
	number := uint32(0)
	apply := func() {
		t.Helper()
		detail, _ := c.request("GET", path, "", nil)
		number++
		raw, _ := json.Marshal(AdminModeration{Kind: "redact", Ranges: []app.RedactionRange{{First: number, Last: number, Mode: "aboon"}}})
		res, body := c.request("POST", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {detail.Header.Get("X-CSRF-Token")}, "If-Match": {detail.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
	}
	apply()
	apply()
	res, body := c.request("GET", path+"?limit=1", "", nil)
	var page struct {
		Data struct {
			Deletions []deletionHTTPView `json:"deletions"`
		} `json:"data"`
		Next string `json:"next_cursor"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &page) != nil || len(page.Data.Deletions) != 1 || page.Next == "" {
		t.Fatal(res.StatusCode, body)
	}
	first := page.Data.Deletions[0].ID
	next := path + "?" + url.Values{"cursor": {page.Next}}.Encode()
	res, body = c.request("GET", next, "", nil)
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &page) != nil || len(page.Data.Deletions) != 1 || page.Next != "" || page.Data.Deletions[0].ID == first {
		t.Fatal(res.StatusCode, body)
	}
	res, body = c.request("GET", strings.TrimPrefix(path, "/api/v1")+"?limit=1", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "次のページ") {
		t.Fatal("HTML history", res.StatusCode, body)
	}
	apply()
	res, _ = c.request("GET", next, "", nil)
	if res.StatusCode != 409 {
		t.Fatal("history version changed", res.StatusCode)
	}
	res, _ = c.request("GET", path+"?unknown=1", "", nil)
	if res.StatusCode != 400 {
		t.Fatal("unknown filter", res.StatusCode)
	}
}
