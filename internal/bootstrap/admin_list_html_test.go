// 共通HTMLページを実HTTPで連結し、経路転用・取得版変更・旧page互換を検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"oimobbs/internal/domain"
)

func TestAdminListHTML(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "list", "一覧1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateBoard(t.Context(), "other", "一覧2"); err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	c.reauth(adminTestSecret)
	list, _ := c.request("GET", "/api/v1/administrators", "", nil)
	input := accountInput{Login: "list.viewer", Display: "一覧閲覧", Password: "private-list-test-password", Access: AdministratorAccess{Role: "moderator", Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true}}
	res, _, body := c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	rulesPath := "/api/v1/boards/" + board.ID.String() + "/rules"
	for i := range 2 {
		detail, _ := c.rules(board.ID)
		rule := AdminRuleInput{Target: fmt.Sprintf("一覧規制%d", i), Operations: []string{"reply"}, Minutes: 60, Reason: "manual", Match: &AdminRuleMatch{"body", "contains", "deny"}}
		raw, _ := json.Marshal(rule)
		res, body = c.request("POST", rulesPath, string(raw), http.Header{"Content-Type": {"application/json"}, "X-Csrf-Token": {detail.Header.Get("X-CSRF-Token")}, "If-Match": {detail.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	for i := range 2 {
		created, err := sendForm(form, url.Values{"bbs": {"list"}, "subject": {fmt.Sprintf("ページ%d", i)}, "MESSAGE": {"本文"}, "oimo_request_id": {fmt.Sprintf("html-page-create-%04d", i)}})
		if err != nil || !created.Accepted {
			t.Fatal(err, created)
		}
	}
	nextRE := regexp.MustCompile(`<a href="([^"]+)">次のページ</a>`)
	for _, path := range []string{"/boards", "/administrators", strings.TrimPrefix(rulesPath, "/api/v1"), fmt.Sprintf("/boards/%s/threads", board.ID)} {
		t.Run(path, func(t *testing.T) {
			first, page := c.request("GET", path+"?limit=1", "", nil)
			match := nextRE.FindStringSubmatch(page)
			if first.StatusCode != 200 || len(match) != 2 {
				t.Fatal(first.StatusCode, page)
			}
			next := html.UnescapeString(match[1])
			last, body := c.request("GET", next, "", nil)
			if last.StatusCode != 200 || nextRE.MatchString(body) || body == page {
				t.Fatal("continuation", last.StatusCode, body)
			}
			query := strings.SplitN(next, "?", 2)[1]
			other, _ := c.request("GET", "/api/v1/boards?"+query, "", nil)
			if other.StatusCode != 400 {
				t.Fatal("route transfer", other.StatusCode)
			}
			bad, _ := c.request("GET", path+"?limit=201", "", nil)
			if bad.StatusCode != 400 {
				t.Fatal("limit", bad.StatusCode)
			}
		})
	}
	threadPath := fmt.Sprintf("/boards/%s/threads", board.ID)
	res, body = c.request("GET", threadPath+"?page=1", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "ページ0") || !strings.Contains(body, "ページ1") {
		t.Fatal("legacy", res.StatusCode, body)
	}
	res, _ = c.request("GET", threadPath+"?page=1&limit=1", "", nil)
	if res.StatusCode != 400 {
		t.Fatal("mixed query", res.StatusCode)
	}
	// 古いHTMLのcursorも、取得結果が変わったら409になる。
	res, body = c.request("GET", "/boards?limit=1", "", nil)
	next := html.UnescapeString(nextRE.FindStringSubmatch(body)[1])
	if _, err = repo.CreateBoard(t.Context(), "third", "一覧3"); err != nil {
		t.Fatal(err)
	}
	res, _ = c.request("GET", next, "", nil)
	if res.StatusCode != 409 {
		t.Fatal("stale HTML cursor", res.StatusCode)
	}
}
