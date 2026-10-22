// 検索順序・管理絞り込み・板別投稿案内の利用経路を検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/app"
)

func TestSearchOrderBoundedSelection(t *testing.T) {
	for _, order := range []string{"", "newest", "oldest", "responses"} {
		t.Run(order, func(t *testing.T) {
			q, err := parseTitleQuery(url.Values{"sort": {order}})
			if err != nil || q.Order != order {
				t.Fatal(q, err)
			}
			rows := searchRowsFixture(6000)
			for i := range rows {
				rows[i].Count = uint32(i % 17)
			}
			c := titleCollector{order: order}
			for _, row := range rows {
				if err := c.add(row, func() *app.PostingSnapshot { return &app.PostingSnapshot{} }); err != nil {
					t.Fatal(err)
				}
			}
			before := func(a, b titleRow) bool {
				if order == "oldest" && a.Created != b.Created {
					return a.Created < b.Created
				}
				if order == "responses" && a.Count != b.Count {
					return a.Count > b.Count
				}
				return titleNewer(a, b)
			}
			sort.Slice(rows, func(i, j int) bool { return before(rows[i], rows[j]) })
			sort.Slice(c.rows, func(i, j int) bool { return titleBefore(c.rows[i], c.rows[j]) })
			if len(c.rows) != 5000 {
				t.Fatal(len(c.rows))
			}
			for i, got := range c.rows {
				want := rows[i]
				if got.Board.ID != want.Board.ID || got.Key != want.Key || got.Created != want.Created || got.Count != want.Count {
					t.Fatalf("row %d differs", i)
				}
			}
		})
	}
	for _, v := range []url.Values{{"sort": {"random"}}, {"sort": {"newest", "oldest"}}} {
		if _, err := parseTitleQuery(v); err == nil {
			t.Fatal("invalid sort accepted")
		}
	}
}

func TestAdminThreadFilterCursorBinding(t *testing.T) {
	s := adminauth.Session{}
	path := "/boards/" + strings.Repeat("1", 32) + "/threads"
	now := time.Now()
	r := httptest.NewRequest("GET", path+"?q=Topic&limit=1", nil)
	page, err := adminListSlice(r, s, "rev", []string{"1", "2"}, now)
	if err != nil || page.Next == "" {
		t.Fatal(page, err)
	}
	for _, query := range []string{"Topic", "Other", ""} {
		r = httptest.NewRequest("GET", path+"?"+url.Values{"q": {query}, "cursor": {page.Next}}.Encode(), nil)
		_, err = adminListSlice(r, s, "rev", []string{"1", "2"}, now)
		if (err == nil) != (query == "Topic") {
			t.Fatal(query, err)
		}
	}
	r = httptest.NewRequest("GET", "/boards?q=Topic", nil)
	if _, err := adminListSlice(r, s, "rev", nil, now); err == nil {
		t.Fatal("filter accepted on unrelated route")
	}
}

func TestPostingFormCurrentBoardRules(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(context.Background(), "guide", "案内")
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	client.login(adminTestSecret)
	res, b := client.board(board.ID.String())
	edit := b.Settings
	edit.Input.NameRequired = true
	edit.Input.BodyBytes = 128
	edit.Input.BodyLines = 4
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-Csrf-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"posting-guide-change-01"}}
	// 既存の管理保存経路を使い、フォームへ反映される確定値を変更する。
	patchBoardForGuide(t, client, board.ID.String(), edit, headers)
	request := func() string {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9080/web/post?bbs=guide", nil)
		w := httptest.NewRecorder()
		repo.WebPostingHandler(board.ID, nil).ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	body := request()
	for _, text := range []string{"名前（必須）", "128バイト", "4行", `name="FROM" autocomplete="off" required`} {
		if !strings.Contains(body, text) {
			t.Fatal("missing guide", text)
		}
	}
	res, b = client.board(board.ID.String())
	edit = b.Settings
	edit.Create = "disabled"
	headers.Set("If-Match", res.Header.Get("ETag"))
	headers.Set("Idempotency-Key", "posting-guide-change-02")
	patchBoardForGuide(t, client, board.ID.String(), edit, headers)
	body = request()
	if !strings.Contains(body, "スレッド作成を停止しています") || strings.Contains(body, `name="MESSAGE"`) {
		t.Fatal("disabled form", body)
	}
}

func patchBoardForGuide(t *testing.T, c *adminClient, id string, edit AdminBoardEdit, headers http.Header) {
	t.Helper()
	raw, err := json.Marshal(edit)
	if err != nil {
		t.Fatal(err)
	}
	res, body := c.request("PATCH", fmt.Sprintf("/api/v1/boards/%s/settings", id), string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
}

func TestSearchOrderAndAdminFilterHTTP(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "browse", "閲覧")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	var firstKey uint64
	for i, title := range []string{"Topic oldest", "Other middle", "Topic newest"} {
		result, err := sendForm(form, url.Values{"bbs": {"browse"}, "subject": {title}, "MESSAGE": {"本文"}, "oimo_request_id": {fmt.Sprintf("browse-feature-create-%d", i)}})
		if err != nil || !result.Accepted {
			t.Fatal(result, err)
		}
		if i == 0 {
			firstKey = result.Key
		}
	}
	result, err := sendForm(form, url.Values{"bbs": {"browse"}, "key": {fmt.Sprint(firstKey)}, "MESSAGE": {"返信"}, "oimo_request_id": {"browse-feature-reply-01"}})
	if err != nil || !result.Accepted {
		t.Fatal(result, err)
	}
	for _, order := range []string{"newest", "oldest", "responses"} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9080/search?board=browse&sort="+order, nil)
		w := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(w, r)
		body := w.Body.String()
		old, newest := strings.Index(body, "Topic oldest"), strings.Index(body, "Topic newest")
		if w.Code != 200 || old < 0 || newest < 0 || (newest < old) != (order == "newest") {
			t.Fatal(order, w.Code, body)
		}
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	path := fmt.Sprintf("/boards/%s/threads", board.ID)
	res, body := c.request("GET", path+"?q=topic&limit=1", "", nil)
	nextRE := regexp.MustCompile(`<a href="([^"]+)">次のページ</a>`)
	match := nextRE.FindStringSubmatch(body)
	if res.StatusCode != 200 || len(match) != 2 || !strings.Contains(body, "Topic newest") || strings.Contains(body, "Other middle") {
		t.Fatal(res.StatusCode, body)
	}
	next := html.UnescapeString(match[1])
	if !strings.Contains(next, "q=topic") {
		t.Fatal(next)
	}
	res, body = c.request("GET", next, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Topic oldest") || strings.Contains(body, "Other middle") || nextRE.MatchString(body) {
		t.Fatal(res.StatusCode, body)
	}
	res, body = c.request("GET", "/api/v1"+path+"?q=TOPIC+newest", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "Topic newest") || strings.Contains(body, "Topic oldest") {
		t.Fatal(res.StatusCode, body)
	}
	for _, query := range []string{"q=x&q=y", "q=" + strings.Repeat("あ", 129), "q=%FF", "q=x&page=1"} {
		res, _ = c.request("GET", path+"?"+query, "", nil)
		if res.StatusCode != 400 {
			t.Fatal(query, res.StatusCode)
		}
	}
}
