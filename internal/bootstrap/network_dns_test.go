// DNS取得方式の管理フォーム・耐久保存・再起動・旧形式互換を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"strings"
	"testing"
)

func TestDNSSettingsFormRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	c := newAdminClient(t, r)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/networks", "", nil)
	if !strings.Contains(page, `name="dns_mode"`) || !strings.Contains(page, "Google Public DNS（HTTPS）") {
		t.Fatal("DNS options missing")
	}
	hidden := pageFields(page)
	fields := url.Values{"csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"dns-settings-save"}}
	fields.Set("action", "settings")
	fields.Set("enabled", "false")
	fields.Set("interval_hours", "24")
	fields.Set("dns_mode", "google_https")
	res, body := c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 {
		t.Fatalf("save status %d, alert %v", res.StatusCode, strings.Contains(body, "入力形式を確認"))
	}
	c.server.Close()
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	view, err := r.networkView()
	if err != nil || view.Config.DNSMode != "google_https" {
		t.Fatal(view, err)
	}
	var site siteState
	if err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != specialNetworkReader {
		t.Fatal(site, err)
	}

	c2 := newAdminClient(t, r)
	defer c2.server.Close()
	if c2.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	get, _ := c2.request("GET", "/api/v1/networks", "", nil)
	legacyConfig := view.Config
	legacyConfig.DNSMode = ""
	legacyRaw, _ := json.Marshal(legacyConfig)
	res, body = c2.request("PATCH", "/api/v1/networks", string(legacyRaw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"legacy-dns-update"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	view, err = r.networkView()
	if err != nil || view.Config.DNSMode != "google_https" {
		t.Fatal("legacy API reset DNS", err)
	}
	// 旧フォームの保存で、新しいDNS選択を失わない。
	form := url.Values{"action": {"settings"}, "enabled": {"false"}, "interval_hours": {"12"}, "csrf": {"x"}, "revision": {"1"}, "request_id": {"x"}}
	req := httptest.NewRequest("POST", "/networks", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	read, err := readNetworkForm(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatal(err)
	}
	next, err := networkFormConfig(view.Config, read)
	if err != nil || next.DNSMode != "google_https" {
		t.Fatal(next, err)
	}
	next.DNSMode = "untrusted"
	if next.validate() == nil {
		t.Fatal("arbitrary DNS allowed")
	}
	old := defaultNetworkConfig()
	raw, _ := json.Marshal(old)
	if !strings.Contains(string(raw), "dns_mode") {
		t.Fatal("current config omitted DNS mode")
	}
	var decoded NetworkConfig
	if err = strictjson.Decode(raw, &decoded); err != nil || decoded.DNSMode != "" {
		t.Fatal(decoded, err)
	}
}

// reverseFlag は明示した許可/拒否を試験要求へ渡す。
func reverseFlag(value bool) *bool { return &value }

func TestReversePermissionLegacyUpdate(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(context.Background(), "legacydns", "DNS互換")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	path := "/api/v1/boards/" + board.ID.String() + "/settings"
	set := func(flag *bool, key string) {
		t.Helper()
		get, body := c.request("GET", path, "", nil)
		var data struct {
			Data AdminBoard `json:"data"`
		}
		if json.Unmarshal([]byte(body), &data) != nil {
			t.Fatal("settings")
		}
		edit := data.Data.Settings
		if edit.Identity == nil {
			edit.Identity = &AdminIdentitySettings{IDMode: "optional", SlipMode: "feature", AllowStrengthen: true, Networks: []identity.NetworkClass{}}
		}
		if edit.Identity.Access == nil {
			edit.Identity.Access = &NetworkAccessSettings{AllowVPN: true}
		}
		edit.Identity.Access.DenyUnresolvedHost = flag
		raw, _ := json.Marshal(edit)
		res, body := c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {key}})
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
	}
	set(reverseFlag(true), "reverse-deny-setting")
	set(nil, "legacy-reverse-update")
	b, err := r.postingOwner(board.ID)
	if err != nil {
		t.Fatal(err)
	}
	check := func(deny bool) {
		t.Helper()
		var saved boardValue
		if err := strictjson.Decode(b.control.State().Rows["board:state"].Value, &saved); err != nil {
			t.Fatal(err)
		}
		if saved.Settings.Identity.Access.denyUnresolvedHost() != deny {
			t.Fatal("reverse policy lost")
		}
	}
	check(true)
	set(reverseFlag(false), "reverse-allow-setting")
	check(false)
}
