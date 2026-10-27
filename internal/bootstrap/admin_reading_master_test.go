// 全体閲覧設定の表示・入力固定・板固有値の保存と、全体OFF時の編集再開を実HTTPで検証する。
package bootstrap

import (
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestReadingMasterPreservesBoardValues(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "masterview", "共通閲覧条件の対象板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	global, h := readingGet(t, c, "/api/v1/reading")
	deny := false
	global.Policy.Enabled = true
	global.Policy.AllowLocalIP = &deny
	global.Policy.Network.JapanOnly = true
	global.Policy.Network.AllowVPN = false
	global.Policy.Network.DeniedKinds = []string{"fixed", "unknown"}
	*global.Policy.Network.DenyUnresolvedHost = true
	global.Policy.DenyCrawlers = true
	global.Policy.DeniedCIDRs = []string{"192.0.2.0/24"}
	if res, body := readingSave(t, c, "/api/v1/reading", global.Policy, readingHeaders(h)); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	path := "/boards/" + board.ID.String() + "/reading"
	res, body := c.request("GET", path, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "現在の掲示板全体の閲覧設定") || !strings.Contains(body, "192.0.2.0/24") {
		t.Fatal("missing current global settings", res.StatusCode)
	}
	for _, name := range []string{"allow_local_ip", "japan_only", "allow_vpn", "deny_unresolved", "deny_crawlers"} {
		if !regexp.MustCompile(`<select name="` + name + `"[^>]*disabled`).MatchString(body) {
			t.Fatal("not locked", name)
		}
	}
	if !regexp.MustCompile(`<input type="checkbox" name="allow_fixed"[^>]*disabled`).MatchString(body) {
		t.Fatal("kind not locked")
	}
	if regexp.MustCompile(`<select name="allow_loopback_ip"[^>]*disabled`).MatchString(body) {
		t.Fatal("independent special address locked")
	}
	if output := os.Getenv("OIMO_MASTER_PAGE_OUTPUT"); output != "" {
		if err := os.WriteFile(output, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// ブラウザが送るhidden値を取得し、disabledでないselect/textareaの値だけを補う。
	f := pageFields(body)
	for _, kind := range permissionKinds {
		if !f.Has("allow_" + kind.Value) {
			f.Set("allow_"+kind.Value, "true")
		}
	}
	for name, value := range map[string]string{"enabled": "true", "allow_loopback_ip": "inherit", "allowed_cidrs": "", "denied_cidrs": "", "denied_agents": "", "denied_countries": ""} {
		f.Set(name, value)
	}
	res, saved := c.request("POST", path, f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("save hidden board values", res.StatusCode, saved)
	}
	local, _ := readingGet(t, c, "/api/v1"+path)
	if local.Policy.AllowLocalIP != nil || local.Policy.Network.JapanOnly || !local.Policy.Network.AllowVPN || local.Policy.Network.denyUnresolvedHost() || local.Policy.DenyCrawlers || len(local.Policy.Network.DeniedKinds) != 0 {
		t.Fatal("global values overwrote board values", local.Policy)
	}
	global, h = readingGet(t, c, "/api/v1/reading")
	global.Policy.Enabled = false
	if res, body := readingSave(t, c, "/api/v1/reading", global.Policy, readingHeaders(h)); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	_, body = c.request("GET", path, "", nil)
	if regexp.MustCompile(`<(select|input)[^>]*disabled`).MatchString(body) || !strings.Contains(body, "OFF：共通の条件は適用されていません") {
		t.Fatal("global OFF still locks fields")
	}
	_, site := c.request("GET", "/reading", "", nil)
	_, admin := c.request("GET", "/admin-access", "", nil)
	if strings.Contains(site, "id=\"reading-master\"") || strings.Contains(admin, "id=\"reading-master\"") {
		t.Fatal("master displayed in independent scopes")
	}
}
