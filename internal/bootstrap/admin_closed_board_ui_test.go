// 閉鎖後の設定画面を閲覧専用にし、古い編集URLや送信からも変更できないことを検証する。
package bootstrap

import (
	"net/http"
	"strings"
	"testing"
)

func TestClosedBoardSettingsAreReadOnly(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "readonly", "閉鎖後の設定")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	base := "/boards/" + board.ID.String()
	res, _ := c.request("GET", base+"/metadata", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("open board metadata", res.StatusCode)
	}
	path, fields := closureForm(t, c, board.ID)
	fields.Set("confirm_key", "readonly")
	res, body := c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("closure", res.StatusCode, body)
	}
	res, body = c.request("GET", base+"/settings", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `class="board-settings-fields" disabled`) || !strings.Contains(body, "設定は変更できません") {
		t.Fatal("read-only settings", res.StatusCode, body)
	}
	for _, route := range []string{"settings", "metadata", "reading", "local-rules", "thread-settings", "rules", "rules/new"} {
		if route != "settings" {
			res, _ = c.request("GET", base+"/"+route, "", nil)
			if res.StatusCode != 303 || res.Header.Get("Location") != base+"/settings" {
				t.Fatal("closed editor", route, res.StatusCode, res.Header)
			}
		}
		for _, prefix := range []string{"", "/api/v1"} {
			res, _ = c.request("POST", prefix+base+"/"+route, "", nil)
			if res.StatusCode != 409 {
				t.Fatal("closed mutation", prefix, route, res.StatusCode)
			}
		}
	}
	res, _ = c.request("GET", "/api/v1"+base+"/settings", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("read-only API", res.StatusCode)
	}
	res, _ = c.request("GET", base+"/threads", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("retained log management", res.StatusCode)
	}
}
