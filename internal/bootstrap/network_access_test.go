// 国/VPNの無料取得・通常フォーム・板間分離・新規投稿規制と復旧を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNetworkAccessFreeFeeds(t *testing.T) {
	var bad atomic.Bool
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/refs/heads/master"):
			writeCountryFixture(w)
		case strings.HasSuffix(r.URL.Path, "/jp/jp.json"):
			fmt.Fprint(w, `{"countryCode":"JP","prefixes":{"ipv4":["1.1.0.0/16"],"ipv6":["2400::/32"]}}`)
		case strings.HasSuffix(r.URL.Path, "/vpn/ipv4.txt"):
			fmt.Fprint(w, "1.1.1.0/24\n2.2.0.0/16\n")
		case strings.HasSuffix(r.URL.Path, "/vpn/ipv6.txt"):
			if bad.Load() {
				fmt.Fprint(w, "2.2.0.0/16\n")
			} else {
				fmt.Fprint(w, "2400:0:1::/48\n")
			}
		default:
			t.Errorf("unexpected feed: %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer feed.Close()
	_, r := adminFixture(t)
	defer r.Close()
	r.mu.Lock()
	r.networkClient = networkTestClient(feed)
	r.mu.Unlock()
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/networks", "", nil)
	hidden := pageFields(page)
	fields := url.Values{"action": {"access_setup"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"access-setup-0001"}}
	response, body := c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	view := waitNetworkAttempt(t, r, 0)
	if view.Error != "" || view.Count != 0 || view.JapanCount != 2 || view.VPN4Count != 2 || view.VPN6Count != 1 {
		t.Fatal(view)
	}
	for _, tc := range []struct{ ip, kind string }{{"1.1.2.1", "unknown"}, {"1.1.1.1", "vpn"}, {"2.2.2.2", "vpn"}, {"3.3.3.3", "foreign"}, {"2400:0:1::1", "vpn"}} {
		probe, e := r.probeNetwork(tc.ip)
		if e != nil || probe.Class.Kind != tc.kind {
			t.Fatal(probe, e)
		}
	}
	good := r.liveNetworks.Load()
	bad.Store(true)
	if e := r.refreshNetworks(context.Background(), true); e == nil {
		t.Fatal("wrong family published")
	}
	if r.liveNetworks.Load() != good {
		t.Fatal("failed refresh discarded last successful tables")
	}
	failed, e := r.networkView()
	if e != nil || failed.Error != "invalid_data" || failed.JapanCount != 2 || failed.VPN6Count != 1 {
		t.Fatal(failed, e)
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != mixedNetworkReader {
		t.Fatal(site, e)
	}
}

func TestNetworkAccessBoardPostingAndRecovery(t *testing.T) {
	cfg, r := adminFixture(t)
	useHealthyPostingCapacity(t, r)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(context.Background(), "news", "接続制限")
	if e != nil {
		t.Fatal(e)
	}
	other, e := r.CreateBoard(context.Background(), "free", "別の板")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	pagePath := "/boards/" + board.ID.String() + "/settings"
	setPolicy := func(japanOnly, allowVPN bool) {
		t.Helper()
		_, page := c.request("GET", pagePath, "", nil)
		fields := pageFields(page)
		// 実画面の初期設定から通常フォームを構成する。
		get, body := c.request("GET", "/api/v1/boards/"+board.ID.String()+"/settings", "", nil)
		if get.StatusCode != 200 {
			t.Fatal(body)
		}
		var envelope struct {
			Data AdminBoard `json:"data"`
		}
		if json.Unmarshal([]byte(body), &envelope) != nil {
			t.Fatal(body)
		}
		values := adminBoardFields(envelope.Data.Settings)
		for k, v := range fields {
			if k == "csrf" || k == "revision" {
				values[k] = v
			}
		}
		values.Set("request_id", domain.NewID().String())
		values.Set("japan_only", fmt.Sprint(japanOnly))
		values.Set("allow_vpn", fmt.Sprint(allowVPN))
		response, body := c.request("POST", pagePath, values.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if response.StatusCode != 303 {
			t.Fatal(response.StatusCode, body)
		}
	}
	override := func(country, vpn string) {
		t.Helper()
		_, page := c.request("GET", "/networks", "", nil)
		h := pageFields(page)
		index := "-1"
		v, e := r.networkView()
		if e != nil {
			t.Fatal(e)
		}
		if len(v.Config.AccessOverrides) > 0 {
			index = "0"
		}
		f := url.Values{"action": {"access_save"}, "csrf": {h.Get("csrf")}, "revision": {h.Get("revision")}, "request_id": {domain.NewID().String()}, "index": {index}, "cidr": {"127.0.0.1"}, "country": {country}, "vpn": {vpn}}
		response, body := c.request("POST", "/networks", f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if response.StatusCode != 200 {
			t.Fatal(response.StatusCode, body)
		}
	}
	setPolicy(true, false)
	form := formServer(t, r, siteID(r.site.State()), board.ID, true)
	defer func() { form.Close() }()
	fields := url.Values{"bbs": {"news"}, "subject": {"接続試験"}, "MESSAGE": {"本文"}, "oimo_request_id": {"access-first-create"}}
	if out, e := sendForm(form, fields); e != nil || out.Accepted {
		t.Fatal("unavailable table bypass", out, e)
	}
	override("foreign", "direct")
	if out, e := sendForm(form, fields); e != nil || out.Accepted {
		t.Fatal("foreign bypass", out, e)
	}
	override("jp", "vpn")
	if out, e := sendForm(form, fields); e != nil || out.Accepted {
		t.Fatal("Japanese VPN bypass", out, e)
	}
	// 同じ接続元でも制限のない板は投稿できる。
	otherForm := formServer(t, r, siteID(r.site.State()), other.ID, true)
	otherForm.Client().Jar = form.Client().Jar
	out, e := sendForm(otherForm, url.Values{"bbs": {"free"}, "subject": {"別板"}, "MESSAGE": {"本文"}, "oimo_request_id": {"access-other-create"}})
	otherForm.Close()
	if e != nil || !out.Accepted {
		t.Fatal("board policy leaked", out, e)
	}
	// 許可に変更すると日本VPNのスレ立てを受理し、以後の規制でも受理済み再送は維持する。
	setPolicy(true, true)
	created, e := sendForm(form, fields)
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	setPolicy(true, false)
	if out, e := sendForm(form, fields); e != nil || !out.Accepted || !out.Duplicate {
		t.Fatal("accepted retry changed", out, e)
	}
	reply := url.Values{"bbs": {"news"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"返信"}, "oimo_request_id": {"access-new-reply-01"}}
	if out, e := sendForm(form, reply); e != nil || out.Accepted {
		t.Fatal("legacy reply bypass", out, e)
	}
	// Webでも同じVPN規制を適用する。
	csrf, e := r.IssueWebCSRF(context.Background(), board.ID, "web_reply")
	if e != nil {
		t.Fatal(e)
	}
	reply.Set("csrf", csrf.Token)
	challenge, e := sendWeb(form, reply, []http.Cookie{*csrf.Cookie}, cfg.Public.BaseURL)
	if e != nil {
		t.Fatal(e)
	}
	if challenge.Confirmation != nil {
		challenge, e = sendWeb(form, reply, []http.Cookie{*csrf.Cookie, {Name: "oimo_confirm", Value: challenge.Confirmation.Token}}, cfg.Public.BaseURL)
	}
	if e != nil || challenge.Accepted {
		t.Fatal("web VPN bypass", challenge, e)
	}
	reply.Del("csrf")
	// 正しい鍵だけが国/VPN制限を免除され、無効な鍵は拒否される。
	cap, secret := createTestCap(t, r, c, board.ID, []string{"create", "post"})
	override("foreign", "vpn")
	reply.Set("mail", "sage #cap:"+cap.ID.String()+":"+secret)
	reply.Set("oimo_request_id", "access-cap-reply-01")
	if out, e := sendForm(form, reply); e != nil || !out.Accepted {
		t.Fatal("authenticated cap denied", out, e)
	}
	reply.Set("mail", "sage #cap:"+cap.ID.String()+":"+strings.Repeat("A", 43))
	reply.Set("oimo_request_id", "access-bad-cap-01")
	if out, e := sendForm(form, reply); e != nil || out.Accepted {
		t.Fatal("invalid cap bypass", out, e)
	}
	// 新しい接続制限を知らない旧identity更新でも保存済み制限を維持する。
	api := "/api/v1/boards/" + board.ID.String() + "/settings"
	get, body := c.request("GET", api, "", nil)
	var envelope struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil {
		t.Fatal(body)
	}
	edit := envelope.Data.Settings
	edit.Identity.Access = nil
	raw, _ := json.Marshal(edit)
	response, body := c.request("PATCH", api, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"access-legacy-edit-01"}})
	if response.StatusCode != 200 || !strings.Contains(body, `"japan_only":true,"allow_vpn":false`) {
		t.Fatal(response.StatusCode, body)
	}
	// 制御snapshotの切替後も規制・上書き・キャップ例外を復元する。
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "network-access")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	form.Close()
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	useHealthyPostingCapacity(t, r)
	jar := form.Client().Jar
	form = formServer(t, r, siteID(r.site.State()), board.ID, true)
	form.Client().Jar = jar
	reply.Set("mail", "")
	reply.Set("oimo_request_id", "access-restored-deny")
	if out, e := sendForm(form, reply); e != nil || out.Accepted {
		t.Fatal("restored denial", out, e)
	}
	reply.Set("mail", "sage #cap:"+cap.ID.String()+":"+secret)
	reply.Set("oimo_request_id", "access-restored-cap")
	if out, e := sendForm(form, reply); e != nil || !out.Accepted {
		t.Fatal("restored cap", out, e)
	}
	probe, e := r.probeNetwork("127.0.0.1")
	if e != nil || probe.Access.Country != "foreign" || probe.Access.VPN != "vpn" {
		t.Fatal(probe, e)
	}
	// 削除は通常フォームで行い、取得表なしの不明へ戻る。
	c = newAdminClient(t, r)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/networks", "", nil)
	h := pageFields(page)
	f := url.Values{"action": {"access_delete"}, "csrf": {h.Get("csrf")}, "revision": {h.Get("revision")}, "request_id": {"access-delete-0001"}, "index": {"0"}}
	response, body = c.request("POST", "/networks", f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	probe, e = r.probeNetwork("127.0.0.1")
	if e != nil || probe.Access.Country != "unknown" || probe.Access.VPN != "unknown" {
		t.Fatal(probe, e)
	}
}

func TestNetworkAccessValidationAndErrors(t *testing.T) {
	for _, raw := range []string{`{"japan_only":true}`, `{"japan_only":true,"allow_vpn":false,"extra":true}`, `{"japan_only":"true","allow_vpn":false}`, `{"japan_only":null,"allow_vpn":false}`} {
		var v NetworkAccessSettings
		if strictjson.Decode([]byte(raw), &v) == nil {
			t.Fatal(raw)
		}
	}
	ip := netip.MustParseAddr("1.1.1.1")
	b := &postingBoard{}
	if b.checkNetworkAccess(&NetworkAccessSettings{AllowVPN: true}, ip, false) != nil {
		t.Fatal("permissive default")
	}
	if b.checkNetworkAccess(&NetworkAccessSettings{JapanOnly: true, AllowVPN: false}, ip, true) != nil {
		t.Fatal("cap exemption")
	}
	if b.checkNetworkAccess(&NetworkAccessSettings{JapanOnly: true, AllowVPN: true}, ip, false) != ErrNetworkUnavailable {
		t.Fatal("unknown country permitted")
	}
	if b.checkNetworkAccess(&NetworkAccessSettings{AllowVPN: false}, ip, false) != ErrNetworkUnavailable {
		t.Fatal("unknown VPN permitted")
	}
	// optional拡張の欠落は読み込み可能だが、未知/null/重複は拒否する。
	config := defaultNetworkConfig()
	raw, _ := json.Marshal(config)
	var restored NetworkConfig
	if e := strictjson.Decode(raw, &restored); e != nil {
		t.Fatal(e)
	}
	for _, field := range []string{`"access_overrides":null`, `"access_overrides":[] ,"access_overrides":[]`, `"unknown_access":[]`} {
		bad := append([]byte{'{'}, append([]byte(field+","), raw[1:]...)...)
		if strictjson.Decode(bad, &restored) == nil {
			t.Fatal(field)
		}
	}
	if _, e := compileAccessData(&networkAccessData{Japan: []string{}}, nil); e == nil {
		t.Fatal("empty success table")
	}
	var state networkState
	if strictjson.Decode([]byte(`{"access_data":{"japan":null,"vpn4":null,"vpn6":null}}`), &state) == nil {
		t.Fatal("incomplete state")
	}
}
