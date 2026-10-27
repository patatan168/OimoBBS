// 特殊アドレスの個別許可・拒否、旧保存形式の互換、管理画面の板別導線を確認する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"oimobbs/internal/strictjson"
)

func TestReadingSpecialAddresses(t *testing.T) {
	allow, deny := true, false
	p := defaultReadingPolicy()
	p.Enabled = true
	p.Network.JapanOnly = true
	p.Network.AllowVPN = false
	p.Network.DeniedKinds = []string{"unknown"}
	p.AllowLocalIP, p.AllowLoopbackIP = &allow, &deny
	for _, tc := range []struct {
		ip      string
		allowed bool
	}{
		{"10.0.0.1", true}, {"172.16.0.1", true}, {"192.168.0.1", true}, {"169.254.1.1", true}, {"fd00::1", true}, {"fe80::1", true},
		{"127.0.0.1", false}, {"::1", false}, {"::ffff:127.0.0.1", false}, {"8.8.8.8", false},
	} {
		v, err := compileReadingPolicy(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := v.check(nil, netip.MustParseAddr(tc.ip), "browser") == nil; got != tc.allowed {
			t.Fatalf("%s: allowed=%v", tc.ip, got)
		}
	}
	p.AllowLocalIP, p.AllowLoopbackIP = &deny, &allow
	v, _ := compileReadingPolicy(p)
	if v.check(nil, netip.MustParseAddr("10.0.0.1"), "") == nil || v.check(nil, netip.MustParseAddr("::1"), "") != nil {
		t.Fatal("independent choices")
	}
	p.DeniedCIDRs = []string{"127.0.0.0/8"}
	p.DeniedAgents = []string{"bad-client"}
	v, _ = compileReadingPolicy(p)
	if v.check(nil, netip.MustParseAddr("127.0.0.1"), "") == nil || v.check(nil, netip.MustParseAddr("::1"), "bad-client") == nil {
		t.Fatal("IP or UA rejection bypassed")
	}
	p.Enabled = false
	v, _ = compileReadingPolicy(p)
	if v.check(nil, netip.MustParseAddr("10.0.0.1"), "") != nil {
		t.Fatal("OFF")
	}
}

func TestReadingSpecialLegacyAndStrictJSON(t *testing.T) {
	p := defaultReadingPolicy()
	raw, _ := json.Marshal(p)
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	delete(fields, "allow_local_ip")
	delete(fields, "allow_loopback_ip")
	legacy, _ := json.Marshal(fields)
	var restored ReadingPolicy
	if err := strictjson.Decode(legacy, &restored); err != nil || restored.AllowLocalIP != nil || restored.AllowLoopbackIP != nil {
		t.Fatal("legacy", err)
	}
	fields["allow_local_ip"] = json.RawMessage("true")
	partial, _ := json.Marshal(fields)
	if strictjson.Decode(partial, &restored) == nil {
		t.Fatal("partial new format accepted")
	}
	for _, value := range []string{`"true"`, `0`, `{}`} {
		fields["allow_local_ip"] = json.RawMessage(value)
		fields["allow_loopback_ip"] = json.RawMessage("false")
		invalid, _ := json.Marshal(fields)
		if strictjson.Decode(invalid, &restored) == nil {
			t.Fatal("invalid type", value)
		}
	}
}

func TestReadingSpecialNavigationAndPersistence(t *testing.T) {
	cfg, repo := adminFixture(t)
	board, err := repo.CreateBoard(t.Context(), "specialip", "特殊IP板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	base := "/boards/" + board.ID.String()
	for _, tc := range []struct{ path, link string }{{"/boards", base + "/reading"}, {base + "/settings", base + "/reading"}, {base + "/reading", base + "/settings"}} {
		res, body := c.request("GET", tc.path, "", nil)
		if res.StatusCode != 200 || !strings.Contains(body, `href="`+tc.link+`"`) {
			t.Fatalf("navigation %s: %d", tc.path, res.StatusCode)
		}
	}
	route := "/api/v1" + base + "/reading"
	view, headers := readingGet(t, c, route)
	allow, deny := true, false
	view.Policy.Enabled = true
	view.Policy.AllowLocalIP, view.Policy.AllowLoopbackIP = &deny, &allow
	if res, body := readingSave(t, c, route, view.Policy, readingHeaders(headers)); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	_, body := c.request("GET", base+"/reading", "", nil)
	if !strings.Contains(body, `name="allow_local_ip"`) || !strings.Contains(body, `name="allow_loopback_ip"`) {
		t.Fatal("missing selectors")
	}
	adminView, adminHeaders := readingGet(t, c, "/api/v1/admin-access")
	adminView.Policy.Enabled = true
	adminView.Policy.AllowLoopbackIP = &deny
	if res, rejected := readingSave(t, c, "/api/v1/admin-access", adminView.Policy, readingHeaders(adminHeaders)); res.StatusCode != 422 || !strings.Contains(rejected, "ADMIN_SELF_LOCKOUT") {
		t.Fatal("loopback self lockout", res.StatusCode, rejected)
	}
	f := pageFields(body)
	for name, value := range map[string]string{
		"enabled": "true", "allow_local_ip": "false", "allow_loopback_ip": "true",
		"japan_only": "false", "allow_vpn": "true", "deny_unresolved": "false", "deny_crawlers": "false",
		"allowed_cidrs": "", "denied_cidrs": "", "denied_agents": "", "denied_countries": "",
	} {
		f.Set(name, value)
	}
	res, saved := c.request("POST", base+"/reading", f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("HTML save", res.StatusCode, saved)
	}
	view, _ = readingGet(t, c, route)
	if view.Policy.AllowLocalIP == nil || *view.Policy.AllowLocalIP || view.Policy.AllowLoopbackIP == nil || !*view.Policy.AllowLoopbackIP {
		t.Fatal("HTML choices lost")
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if repo.checkReading(board.ID.String(), netip.MustParseAddr("10.0.0.1"), "") == nil || repo.checkReading(board.ID.String(), netip.MustParseAddr("127.0.0.1"), "") != nil {
		t.Fatal("lost individual settings")
	}
}
