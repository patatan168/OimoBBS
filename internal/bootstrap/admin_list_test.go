// 共通カーソルの境界と、実HTTPでの認可・ページ連結・取得版変更を検査する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestAdminListCursorBounds(t *testing.T) {
	now := time.Now()
	session := adminauth.Session{}
	keys := []string{"a", "b", "c"}
	request := httptest.NewRequest("GET", "http://local/api/v1/caps?limit=2", nil)
	first, err := adminListSlice(request, session, "v1", keys, now)
	if err != nil || first.End != 2 || first.Next == "" {
		t.Fatal(err)
	}
	request = httptest.NewRequest("GET", "http://local/api/v1/caps?"+url.Values{"cursor": {first.Next}}.Encode(), nil)
	last, err := adminListSlice(request, session, "v1", keys, now.Add(time.Minute))
	if err != nil || last.Start != 2 || last.End != 3 || last.Next != "" {
		t.Fatal("continuation", err)
	}
	if _, err = adminListSlice(request, session, "v2", keys, now); err == nil {
		t.Fatal("changed version")
	}
	if _, err = adminListSlice(request, session, "v1", keys, now.Add(10*time.Minute)); err == nil {
		t.Fatal("expired")
	}
	for _, query := range []string{"limit=0", "limit=201", "limit=01", "limit=2&limit=3", "cursor=", "unknown=x", url.Values{"cursor": {first.Next}, "limit": {"3"}}.Encode(), url.Values{"cursor": {first.Next + "x"}}.Encode()} {
		request = httptest.NewRequest("GET", "http://local/api/v1/caps?"+query, nil)
		if _, err = adminListSlice(request, session, "v1", keys, now); err == nil {
			t.Fatal("invalid", query)
		}
	}
	request = httptest.NewRequest("GET", "http://local/api/v1/boards?"+url.Values{"cursor": {first.Next}}.Encode(), nil)
	if _, err = adminListSlice(request, session, "v1", keys, now); err == nil {
		t.Fatal("route transfer")
	}
}

func TestAdminListHTTP(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(t.Context(), "list", "一覧試験")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	for range 3 {
		createTestCap(t, r, c, board.ID, []string{"post"})
	}
	get := func(path string) (*http.Response, []AdminCap, string) {
		t.Helper()
		res, body := c.request("GET", path, "", nil)
		var page struct {
			Data []AdminCap `json:"data"`
			Next string     `json:"next_cursor"`
		}
		if res.StatusCode == 200 && json.Unmarshal([]byte(body), &page) != nil {
			t.Fatal("page", body)
		}
		return res, page.Data, page.Next
	}
	res, rows, next := get("/api/v1/caps?limit=2")
	if res.StatusCode != 200 || len(rows) != 2 || next == "" {
		t.Fatal("first page", res.StatusCode)
	}
	res, last, end := get("/api/v1/caps?" + url.Values{"cursor": {next}}.Encode())
	if res.StatusCode != 200 || len(last) != 1 || end != "" || last[0].ID == rows[0].ID || last[0].ID == rows[1].ID {
		t.Fatal("last page")
	}
	other := newAdminClient(t, r)
	defer other.server.Close()
	if other.login(adminTestSecret) != 303 || other.reauth(adminTestSecret) != 200 {
		t.Fatal("other login")
	}
	res, _ = other.request("GET", "/api/v1/caps?"+url.Values{"cursor": {next}}.Encode(), "", nil)
	if res.StatusCode != 400 {
		t.Fatal("session transfer", res.StatusCode)
	}
	createTestCap(t, r, c, board.ID, []string{"post"})
	res, _, _ = get("/api/v1/caps?" + url.Values{"cursor": {next}}.Encode())
	if res.StatusCode != 409 {
		t.Fatal("changed version", res.StatusCode)
	}
	for _, path := range []string{"/api/v1/caps?limit=0", "/api/v1/boards?limit=201", "/api/v1/administrators?unknown=x", "/api/v1/boards/" + board.ID.String() + "/rules?cursor=x"} {
		res, _ = c.request("GET", path, "", nil)
		if res.StatusCode != 400 {
			t.Fatal("list query", path, res.StatusCode)
		}
	}
	for _, path := range []string{"/api/v1/boards?limit=1", "/api/v1/administrators?limit=1", "/api/v1/boards/" + board.ID.String() + "/rules?limit=1", "/api/v1/boards/" + board.ID.String() + "/threads?limit=1"} {
		res, _ = c.request("GET", path, "", nil)
		if res.StatusCode != 200 {
			t.Fatal("list route", path, res.StatusCode)
		}
	}
}

func TestAdminListDefaultAndMaximum(t *testing.T) {
	keys := make([]string, 250)
	for i := range keys {
		keys[i] = domain.NewID().String()
	}
	for _, tt := range []struct {
		query string
		want  int
	}{{"", 50}, {"?limit=200", 200}} {
		request := httptest.NewRequest("GET", "http://local/api/v1/caps"+tt.query, nil)
		page, err := adminListSlice(request, adminauth.Session{}, "v", keys, time.Now())
		if err != nil || page.End != tt.want || page.Next == "" {
			t.Fatal(tt, err)
		}
	}
}
