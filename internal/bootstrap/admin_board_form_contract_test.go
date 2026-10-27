// 現行の板設定画面が送らない旧Cookie・投稿間隔設定の省略と厳格な部分入力拒否を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/domain"
)

func TestAdminBoardFormOmitsGlobalPostingSettings(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "formcontract", "設定保存")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/boards/" + board.ID.String() + "/settings"
	res, current := c.board(board.ID.String())
	before, _ := json.Marshal(current.Settings.anonymous())
	fields := adminBoardFields(current.Settings)
	fields.Set("csrf", res.Header.Get("X-CSRF-Token"))
	fields.Set("revision", res.Header.Get("ETag"))
	fields.Set("request_id", domain.NewID().String())
	for _, name := range []string{"cookie_mode", "token_wait_seconds", "rate_enabled", "reply_seconds", "reply_burst", "create_seconds", "create_burst", "create_window_limit"} {
		fields.Del(name)
	}
	for _, tc := range []struct{ name, value string }{
		{"cookie_mode", "required"}, {"token_wait_seconds", "0"}, {"rate_enabled", "false"}, {"reply_seconds", "1"}, {"unexpected", "true"},
	} {
		copyFields := url.Values{}
		for name, values := range fields {
			copyFields[name] = append([]string{}, values...)
		}
		copyFields.Set(tc.name, tc.value)
		response, _ := c.request("POST", path, copyFields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if response.StatusCode != 400 {
			t.Fatal("partial or unknown field accepted", tc.name, response.StatusCode)
		}
	}
	fields.Set("auto_reports_enabled", "false")
	response, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 303 {
		t.Fatal("current form rejected", response.StatusCode, body)
	}
	_, saved := c.board(board.ID.String())
	after, _ := json.Marshal(saved.Settings.anonymous())
	if string(before) != string(after) || saved.Settings.AutoReportsEnabled == nil || *saved.Settings.AutoReportsEnabled {
		t.Fatal("posting settings changed or report toggle lost")
	}
	_, page := c.request("GET", path, "", nil)
	if strings.Contains(page, `name="cookie_mode"`) || strings.Contains(page, `name="rate_enabled"`) {
		t.Fatal("obsolete global inputs rendered")
	}
}
