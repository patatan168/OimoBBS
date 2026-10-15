// 固定・携帯混在の分類、独立した許可設定、保存形式のreader境界を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestMixedNetworkClassificationAndPermissions(t *testing.T) {
	rows := []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "mixed", Label: "混在", Suffix: "0", Provider: "test"}}
	automatic, err := identity.CompileNetworks(rows, 10)
	if err != nil {
		t.Fatal(err)
	}
	classifier := &identity.NetworkClassifier{Automatic: automatic}
	ip := netip.MustParseAddr("192.0.2.1")
	for _, kind := range []string{"fixed", "mobile", "unknown", "mixed"} {
		policy := &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{kind}}
		if err := policy.validate(); err != nil {
			t.Fatal(err)
		}
		err := checkNetworkPermission(classifier, policy, ip)
		if (err == ErrNetworkPermission) != (kind == "mixed") {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	services, err := identity.CompileNetworks([]identity.NetworkClass{{CIDR: "192.0.2.1/32", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}}, 10)
	if err != nil {
		t.Fatal(err)
	}
	classifier.Services = services
	if got := classifier.Classify(nil, ip); got.Kind != "fixed" || got.Provider != "test" {
		t.Fatal(got)
	}
}

func TestMixedNetworkPresets(t *testing.T) {
	expected := []uint32{4713, 2516, 17676, 17511}
	for _, s := range defaultNetworkSources() {
		if slices.Contains(expected, s.ASN) && s.Kind != "mixed" {
			t.Fatalf("AS%d: %s", s.ASN, s.Kind)
		}
	}
	for _, c := range defaultNetworkCategories() {
		if c.ID == "mixed" && c.Kind == "mixed" {
			return
		}
	}
	t.Fatal("missing mixed category")
}

func TestMixedNetworkReaderAndPersistence(t *testing.T) {
	cfg, repo := adminFixture(t)
	state, err := loadNetworkState(repo.site.State())
	if err != nil {
		t.Fatal(err)
	}
	state.Version = 1
	state.Config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "mixed", Label: "混在", Suffix: "0"}}
	repo.mu.Lock()
	err = repo.publishNetworks(state, nil, "mixed_test", nil)
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var site siteState
	if err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != 85 {
		t.Fatal(site.MinimumReader, err)
	}
	snapshot := repo.site.State()
	site.MinimumReader = 84
	row := snapshot.Rows["site:state"]
	row.Value, _ = json.Marshal(site)
	snapshot.Rows["site:state"] = row
	if _, err = inspectSiteState(snapshot, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("reader84 accepted mixed")
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.liveNetworks.Load().Classify(nil, netip.MustParseAddr("192.0.2.1")).Kind; got != "mixed" {
		t.Fatal(got)
	}
	board := boardValue{Settings: defaultBoardSettings()}
	board.Settings.Identity.Access = &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{"mixed"}}
	if err = validateIdentityReader(siteState{MinimumReader: 84}, board); err != store.ErrCorrupt {
		t.Fatal("board reader", err)
	}
	p := defaultReadingPolicy()
	p.Network.DeniedKinds = []string{"mixed"}
	raw, _ := json.Marshal(p)
	if got := readingMinimumReader(raw); got != 85 {
		t.Fatal("reading reader", got)
	}
}

// 管理画面の通常フォームから混在上書きを保存し、閲覧APIの拒否設定も再取得する。
func TestMixedNetworkManagement(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, body := client.request("GET", "/networks", "", nil)
	for _, selectHTML := range regexp.MustCompile(`(?s)<select name="kind">.*?</select>`).FindAllString(body, -1) {
		if !strings.Contains(selectHTML, `value="mixed"`) {
			t.Fatal("mixed choice missing from kind selector")
		}
	}
	if !strings.Contains(body, `value="mixed"`) || !strings.Contains(body, "固定・携帯混在") {
		t.Fatal("missing mixed choice")
	}
	hidden := pageFields(body)
	fields := url.Values{"action": {"override_save"}, "index": {"-1"}, "cidr": {"192.0.2.0/24"}, "display_preset": {"mixed"}, "kind": {"mixed"}, "label": {"ﾜｯﾁｮｲ"}, "suffix": {"0"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {domain.NewID().String()}}
	response, body := client.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	if got := repo.liveNetworks.Load().Classify(nil, netip.MustParseAddr("192.0.2.1")).Kind; got != "mixed" {
		t.Fatal(got)
	}
	board, err := repo.CreateBoard(t.Context(), "mixedtest", "混在分類")
	if err != nil {
		t.Fatal(err)
	}
	route := "/api/v1/boards/" + board.ID.String() + "/reading"
	view, headers := readingGet(t, client, route)
	view.Policy.Network.DeniedKinds = []string{"mixed"}
	response, body = readingSave(t, client, route, view.Policy, readingHeaders(headers))
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	restored, _ := readingGet(t, client, route)
	if !slices.Equal(restored.Policy.Network.DeniedKinds, []string{"mixed"}) {
		t.Fatal(restored.Policy)
	}
}

func TestMixedNetworkConditionAndReader(t *testing.T) {
	condition := denialCondition{Field: "line", Operator: "exact", Value: "mixed"}
	rule := compiledRuleCondition{condition: condition}
	for _, kind := range []string{"mixed", "fixed", "mobile", "mvno", "unknown"} {
		if got := rule.matches(netip.MustParseAddr("192.0.2.1"), postinput.Input{}, domain.Hash{}, nil, nil, kind); got != (kind == "mixed") {
			t.Fatal(kind, got)
		}
	}
	if !mixedNetworkRule([]denialCondition{condition}) {
		t.Fatal("missing mixed rule")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.mu.Lock()
	err := repo.enableDenials(domain.NewID(), true, false, false, false, true, false, false, true)
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	var site siteState
	if err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != mixedNetworkReader {
		t.Fatal(site.MinimumReader, err)
	}
}
