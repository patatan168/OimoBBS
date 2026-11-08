// 国内事業者の国条件補完を板別の投稿・閲覧設定と実HTTP投稿、再起動で検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"testing"
)

// saveDomesticBoardPolicy は通常の管理APIから板別事業者・国・VPN条件を耐久保存する。
func saveDomesticBoardPolicy(t *testing.T, c *adminClient, owner domain.ID, provider string, countries []string, allowVPN bool) {
	t.Helper()
	path := "/api/v1/boards/" + owner.String() + "/settings"
	res, body := c.request("GET", path, "", nil)
	var envelope struct {
		Data AdminBoard `json:"data"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &envelope) != nil {
		t.Fatal(res.StatusCode, body)
	}
	edit := envelope.Data.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "none", AllowStrengthen: true,
		Networks: []identity.NetworkClass{{CIDR: "127.0.0.0/8", Kind: "unknown", Label: "事業者", Suffix: "0", Provider: provider}},
		Access:   &NetworkAccessSettings{JapanOnly: true, AllowVPN: allowVPN, DeniedCountries: countries, DeniedKinds: []string{}},
	}
	rates := defaultRateSettings()
	rates.Enabled = false
	edit.Rates = &rates
	raw, _ := json.Marshal(edit)
	res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {domain.NewID().String()}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
}

// publishDomesticPostingCountry は模擬接続元の元の国情報・VPN属性を保存し、復旧も同じ表で検査する。
func publishDomesticPostingCountry(t *testing.T, repo *Repository, country, vpn string) {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	state, err := loadNetworkState(repo.site.State())
	if err != nil {
		t.Fatal(err)
	}
	state.Version++
	state.Config.Overrides = []identity.NetworkClass{{CIDR: "127.0.0.0/8", Kind: "unknown", Label: "事業者", Suffix: "0", Provider: "biglobe"}}
	code := ""
	if country == "foreign" {
		code = "US"
	}
	state.Config.AccessOverrides = []identity.AccessOverride{{CIDR: "127.0.0.0/8", Country: country, CountryCode: code, VPN: vpn}}
	if err := repo.publishNetworks(state, nil, "network_test", nil); err != nil {
		t.Fatal(err)
	}
}

// TestNetworkDomesticBoardPosting は同じ接続元でも板別設定で結果が変わり、全体拒否と復旧を維持する。
func TestNetworkDomesticBoardPosting(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	useHealthyPostingCapacity(t, repo)
	a, err := repo.CreateBoard(t.Context(), "domestic", "国内事業者")
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.CreateBoard(t.Context(), "foreignisp", "国外事業者")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	saveDomesticBoardPolicy(t, c, a.ID, "biglobe", []string{"US"}, false)
	saveDomesticBoardPolicy(t, c, b.ID, "aws", []string{"US"}, false)
	publishDomesticPostingCountry(t, repo, "foreign", "direct")
	policy := defaultReadingPolicy()
	policy.Enabled, policy.Network.JapanOnly = true, true
	policy.Network.DeniedCountries = []string{"US"}
	saveReading := func(route string, p ReadingPolicy) {
		t.Helper()
		_, headers := readingGet(t, c, route)
		res, body := readingSave(t, c, route, p, readingHeaders(headers))
		if res.StatusCode != 200 {
			t.Fatal(res.StatusCode, body)
		}
	}
	saveReading("/api/v1/reading", policy)
	saveReading("/api/v1/boards/"+a.ID.String()+"/reading", policy)
	saveReading("/api/v1/boards/"+b.ID.String()+"/reading", policy)
	ip := netip.MustParseAddr("127.0.0.1")
	if repo.checkReading(a.ID.String(), ip, "browser") != nil || repo.checkReading(b.ID.String(), ip, "browser") == nil {
		t.Fatal("board reading overrides ignored")
	}
	policy.Enabled = false
	saveReading("/api/v1/boards/"+b.ID.String()+"/reading", policy)
	form := formServer(t, repo, siteID(repo.site.State()), a.ID)
	defer func() { form.Close() }()
	created, err := sendForm(form, url.Values{"bbs": {a.Key}, "subject": {"国内試験"}, "MESSAGE": {"本文"}, "oimo_request_id": {"domestic-first-create"}})
	if err != nil || !created.Accepted {
		t.Fatal("domestic board rejected", created, err)
	}
	other := formServer(t, repo, siteID(repo.site.State()), b.ID)
	other.Client().Jar = form.Client().Jar
	denied, err := sendForm(other, url.Values{"bbs": {b.Key}, "subject": {"国外試験"}, "MESSAGE": {"本文"}, "oimo_request_id": {"domestic-other-create"}})
	other.Close()
	if err != nil || denied.Accepted {
		t.Fatal("foreign board override ignored", denied, err)
	}
	reply := func(id string, allowed bool) {
		t.Helper()
		result, err := sendForm(form, url.Values{"bbs": {a.Key}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {id}, "oimo_request_id": {id}})
		if err != nil || result.Accepted != allowed {
			t.Fatal(id, result, err)
		}
	}
	saveDomesticBoardPolicy(t, c, a.ID, "biglobe", []string{"JP"}, false)
	reply("domestic-japan-denied", false)
	saveDomesticBoardPolicy(t, c, a.ID, "biglobe", []string{"US"}, false)
	publishDomesticPostingCountry(t, repo, "auto", "direct")
	reply("domestic-unknown-country", true)
	publishDomesticPostingCountry(t, repo, "foreign", "vpn")
	reply("domestic-vpn-denied", false)
	saveDomesticBoardPolicy(t, c, a.ID, "biglobe", []string{"US"}, true)
	reply("domestic-vpn-permitted", true)
	csrf, err := repo.IssueWebCSRF(t.Context(), a.ID, "web_reply")
	if err != nil {
		t.Fatal(err)
	}
	webFields := url.Values{"bbs": {a.Key}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"Web返信"}, "csrf": {csrf.Token}, "oimo_request_id": {"domestic-web-reply"}}
	web, err := sendWeb(form, webFields, []http.Cookie{*csrf.Cookie}, cfg.Public.BaseURL)
	if err == nil && web.Confirmation != nil {
		web, err = sendWeb(form, webFields, []http.Cookie{*csrf.Cookie, {Name: "oimo_confirm", Value: web.Confirmation.Token}}, cfg.Public.BaseURL)
	}
	if err != nil || !web.Accepted {
		t.Fatal("domestic Web reply rejected", web, err)
	}
	form.Close()
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	useHealthyPostingCapacity(t, repo)
	form = formServer(t, repo, siteID(repo.site.State()), a.ID)
	reply("domestic-after-restart", true)
	if got := repo.liveNetworks.Load().ClassifyAccess(ip); got.CountryCode != "US" || got.Country != "foreign" || got.VPN != "vpn" {
		t.Fatal("original country/VPN changed", got)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login after restart")
	}
	policy.Enabled = true
	policy.Network.DeniedCountries = []string{"JP"}
	saveReading("/api/v1/reading", policy)
	reply("domestic-global-denied", false)
}
