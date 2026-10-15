// 板全体の許可設定を旧形式・通常フォーム・保存/復旧と投稿判定で検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNetworkPermissionsCodec(t *testing.T) {
	old := []byte(`{"japan_only":false,"allow_vpn":true}`)
	var v NetworkAccessSettings
	if err := strictjson.Decode(old, &v); err == nil {
		t.Fatal("old permissions accepted")
	}
	v = NetworkAccessSettings{AllowVPN: true}
	raw, _ := json.Marshal(v)
	if !strings.Contains(string(raw), `"denied_kinds":[]`) || !strings.Contains(string(raw), `"deny_unresolved_host":null`) {
		t.Fatal(string(raw))
	}
	var w NetworkAccessSettings
	if err := strictjson.Decode(raw, &w); err != nil {
		t.Fatal("current permissions", err)
	}
	for _, bad := range []NetworkAccessSettings{{DeniedKinds: []string{"bad"}}, {DeniedCountries: []string{"US", "US"}}} {
		if err := bad.validate(); err == nil {
			t.Fatal("invalid permissions accepted")
		}
	}
	for _, bad := range []string{`{"japan_only":false,"allow_vpn":true,"denied_kinds":["bad"]}`, `{"japan_only":false,"allow_vpn":true,"denied_countries":["US","US"]}`} {
		if strictjson.Decode([]byte(bad), &w) == nil {
			t.Fatal("accepted invalid permission")
		}
	}
}
func TestNetworkPermissionsClassification(t *testing.T) {
	auto, e := identity.CompileNetworks([]identity.NetworkClass{{CIDR: "1.1.0.0/16", Kind: "mobile", Label: "携帯", Suffix: "S"}, {CIDR: "2.2.0.0/16", Kind: "mvno", Label: "MVNO", Suffix: "M"}}, 40000)
	if e != nil {
		t.Fatal(e)
	}
	countries, e := identity.CompileCountries([]identity.CountryNetwork{{Prefix: netip.MustParsePrefix("1.1.0.0/16"), Code: "JP"}, {Prefix: netip.MustParsePrefix("2.2.0.0/16"), Code: "US"}})
	if e != nil {
		t.Fatal(e)
	}
	var live atomic.Pointer[identity.NetworkClassifier]
	live.Store(&identity.NetworkClassifier{Automatic: auto, Access: &identity.AccessIndex{Countries: countries}})
	b := postingBoard{liveNetworks: &live}
	p := &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{"mobile"}}
	if b.checkNetworkAccess(p, netip.MustParseAddr("1.1.1.1"), false) != ErrNetworkPermission {
		t.Fatal("mobile allowed")
	}
	if b.checkNetworkAccess(p, netip.MustParseAddr("2.2.2.2"), false) != nil {
		t.Fatal("MVNO included in mobile")
	}
	p.DeniedCountries = []string{"US"}
	if b.checkNetworkAccess(p, netip.MustParseAddr("2.2.2.2"), false) != ErrNetworkPermission {
		t.Fatal("country allowed")
	}
	if b.checkNetworkAccess(p, netip.MustParseAddr("2.2.2.2"), true) != nil {
		t.Fatal("cap denied")
	}
	if b.checkNetworkAccess(p, netip.MustParseAddr("3.3.3.3"), false) != ErrNetworkUnavailable {
		t.Fatal("unknown country bypass")
	}
	if validateIdentityReader(siteState{MinimumReader: 33}, boardValue{Settings: boardSettings{Identity: boardIdentity{Access: p}}}) != store.ErrCorrupt {
		t.Fatal("reader gate")
	}
}
func TestNetworkPermissionsCheckboxForm(t *testing.T) {
	v := adminBoardFields(AdminBoardEdit{})
	_ = v
	base := url.Values{}
	for _, name := range adminBoardFieldNames {
		base.Set(name, "")
	}
	base.Set("access_options", "1")
	base.Set("country_scope", "JP US")
	base.Add("allow_country", "JP")
	base.Set("permit_foreign", "on")
	base.Set("permit_vpn", "on")
	for _, o := range permissionKinds {
		if o.Value != "mobile" {
			base.Set("permit_kind_"+o.Value, "on")
		}
	}
	req := httptest.NewRequest("POST", "/", strings.NewReader(base.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out, e := readBoardPermissionForm(httptest.NewRecorder(), req)
	if e != nil {
		t.Fatal(e)
	}
	if out.Get("denied_kinds") != `["mobile"]` || out.Get("denied_countries") != `["US"]` {
		t.Fatal(out)
	}
}

func TestNetworkPermissionsFormRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	board, e := r.CreateBoard(context.Background(), "news", "許可設定")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/boards/" + board.ID.String() + "/settings"
	_, page := c.request("GET", path, "", nil)
	h := pageFields(page)
	if !strings.Contains(page, `name="permit_kind_mobile"`) || !strings.Contains(page, `name="allow_country"`) {
		t.Fatal("checkbox UI missing")
	}
	_, body := c.request("GET", "/api/v1"+path, "", nil)
	var v struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &v) != nil {
		t.Fatal("settings")
	}
	f := adminBoardFields(v.Data.Settings)
	f.Set("csrf", h.Get("csrf"))
	f.Set("revision", h.Get("revision"))
	f.Set("request_id", domain.NewID().String())
	f.Set("access_options", "1")
	f.Set("reverse_options", "1")
	f.Del("deny_unresolved_host")
	f.Set("country_scope", "JP US")
	f.Set("allow_country", "JP")
	f.Set("permit_foreign", "on")
	f.Set("permit_vpn", "on")
	for _, o := range permissionKinds {
		if o.Value != "mobile" {
			f.Set("permit_kind_"+o.Value, "on")
		}
	}
	res, body := c.request("POST", path, f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("save", res.StatusCode, body)
	}
	res, page = c.request("GET", path, "", nil)
	if res.StatusCode != 200 || strings.Contains(page, `name="permit_kind_mobile" checked`) {
		t.Fatal("saved checks")
	}
	check := func(repo *Repository) {
		t.Helper()
		b, e := repo.postingOwner(board.ID)
		if e != nil {
			t.Fatal(e)
		}
		var saved boardValue
		if e = strictjson.Decode(b.control.State().Rows["board:state"].Value, &saved); e != nil {
			t.Fatal(e)
		}
		p := saved.Settings.Identity.Access
		if p == nil || !p.denyUnresolvedHost() || !slices.Equal(p.DeniedKinds, []string{"mobile"}) || !slices.Equal(p.DeniedCountries, []string{"US"}) {
			t.Fatal("permissions lost")
		}
	}
	check(r)
	if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
		t.Fatal(e)
	}
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	check(reopened)
}
