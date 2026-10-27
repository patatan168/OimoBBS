// 国内カタログの実取得対象と、有界並列取得・初回起動の保存境界を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDomesticNetworkCatalogue(t *testing.T) {
	sources := defaultNetworkSources()
	if len(networkSourcePresets) < 211 {
		t.Fatal("domestic ASN coverage too small", len(networkSourcePresets))
	}
	if err := (NetworkConfig{Enabled: true, IntervalHours: 24, Sources: sources, Categories: defaultNetworkCategories(), Overrides: []identity.NetworkClass{}}).validate(); err != nil {
		t.Fatal(err)
	}
	expected := map[uint32]string{138384: "rakuten", 10012: "rakuten", 2527: "sonet", 9600: "sonet", 2518: "biglobe", 4685: "asahi-net", 10013: "freebit", 7679: "qtnet", 18126: "ctc", 18144: "enecom", 24257: "jpne", 55391: "transix", 9617: "jcom", 9365: "itscom", 131160: "wi2", 59126: "nct", 216025: "mullvad", 208172: "proton", 207137: "packethub", 136787: "packethub"}
	for _, source := range sources {
		if provider, ok := expected[source.ASN]; ok {
			if source.Provider != provider {
				t.Fatal("provider identity", source.ASN, source.Provider, provider)
			}
			delete(expected, source.ASN)
		}
	}
	if len(expected) != 0 {
		t.Fatal("missing domestic providers", expected)
	}
	seen := map[string]bool{}
	for _, p := range networkSourcePresets {
		if seen[p.ID] {
			t.Fatal("duplicate preset ID", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestNetworkFetchConcurrentAndBounded(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	arrived := make(chan struct{}, 32)
	release := make(chan struct{})
	defer close(release)
	client := &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		arrived <- struct{}{}
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		var asn uint32
		fmt.Sscanf(req.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn)
		body := fmt.Sprintf(`{"asn":%d,"prefixes":{"ipv4":["198.18.%d.0/24"],"ipv6":[]}}`, asn, asn)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	sources := make([]NetworkSource, 16)
	for i := range sources {
		sources[i] = NetworkSource{Name: fmt.Sprint(i), Type: "asn", ASN: uint32(i + 1), Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0"}
	}
	done := make(chan error, 1)
	go func() { _, err := fetchNetworkRows(ctx, client, sources); done <- err }()
	for i := 0; i < 8; i++ {
		select {
		case <-arrived:
		case <-ctx.Done():
			t.Fatal("sources fetched serially")
		}
	}
	select {
	case <-arrived:
		t.Fatal("more than eight simultaneous requests")
	default:
	}
	// 初回の8要求を解放し、後半も同じ枠で最後まで検証する。
	for i := 0; i < 16; i++ {
		release <- struct{}{}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// 初回の全ASN要求が実際に発行され、取得失敗も保存されることを確認する。
func TestNetworkFirstStartupAttemptsAllDomesticSources(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer repo.Close()
	var mutex sync.Mutex
	requested := map[uint32]bool{}
	client := &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		var asn uint32
		if _, err := fmt.Sscanf(req.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn); err == nil {
			mutex.Lock()
			requested[asn] = true
			mutex.Unlock()
		}
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
	})}
	if err := repo.EnsureStandardNetworks(client); err != nil {
		t.Fatal(err)
	}
	view := waitNetworkAttempt(t, repo, 0)
	mutex.Lock()
	count := len(requested)
	mutex.Unlock()
	if count != len(networkSourcePresets) || !view.Config.Enabled || len(view.Config.Sources) != len(defaultNetworkSources()) || view.Error != "fetch_failed" || view.AppliedVersion != 0 {
		t.Fatal("initial fetch not attempted or failure not retained", count, view)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restored, err := reopened.networkView()
	if err != nil || restored.Attempt != view.Attempt || restored.Error != view.Error || !reflect.DeepEqual(restored.Config, view.Config) {
		t.Fatal("initial setup not durable", restored, err)
	}
}

func TestNetworkDomesticSetupPreservesManualConfiguration(t *testing.T) {
	config := defaultNetworkConfig()
	config.Enabled = false
	config.IntervalHours = 72
	config.Sources = defaultNetworkSources()[:7]
	config.Sources[0].Name = "管理者が変更したOCN"
	config.Sources[0].Kind = "fixed"
	config.Categories[0].Name = "独自の固定表示"
	config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "独自", Suffix: "0"}}
	original := config
	next, err := networkFormConfig(config, url.Values{"action": {"domestic_setup"}})
	if err != nil {
		t.Fatal(err)
	}
	if !next.Enabled || next.IntervalHours != 72 || next.Sources[0] != original.Sources[0] || next.Categories[0] != original.Categories[0] || !reflect.DeepEqual(next.Overrides, original.Overrides) || len(next.Sources) != len(defaultNetworkSources()) {
		t.Fatal("manual settings replaced", next)
	}
	twice, err := networkFormConfig(next, url.Values{"action": {"domestic_setup"}})
	if err != nil || !reflect.DeepEqual(twice, next) {
		t.Fatal("duplicate domestic sources", err)
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.mu.Lock()
	state, err := loadNetworkState(repo.site.State())
	if err == nil {
		state.Version = 1
		state.Config = original
		state.Config.Enabled = false
		err = repo.publishNetworks(state, nil, "network_test", nil)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = repo.EnsureStandardNetworks(nil); err != nil {
		t.Fatal(err)
	}
	view, err := repo.networkView()
	if err != nil || !reflect.DeepEqual(view.Config, state.Config) {
		t.Fatal("startup overwrote existing or disabled settings", err)
	}
}

// 拡張上限は新readerを要求し、旧境界に戻した保存状態を受け入れない。
func TestNetworkDomesticReaderBoundary(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "初回設定"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if err = repo.EnsureStandardNetworks(nil); err != nil {
		t.Fatal(err)
	}
	var site siteState
	if err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != networkZstdReader {
		t.Fatal(site.MinimumReader, err)
	}
	state := repo.site.State()
	if _, err = inspectSiteState(state, site.ID, cfg.Public.BaseURL); err != nil {
		t.Fatal("new startup state rejected", err)
	}
	site.MinimumReader = 80
	row := state.Rows["site:state"]
	row.Value, err = json.Marshal(site)
	if err != nil {
		t.Fatal(err)
	}
	state.Rows["site:state"] = row
	if _, err = inspectSiteState(state, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("reader 80 accepted expanded catalog")
	}

}

// 大規模一覧でも候補カタログは一度だけ描画し、失敗入力を対象の行に戻す。
func TestNetworkDomesticManagementPage(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if err := repo.EnsureStandardNetworks(&http.Client{Transport: networkTestTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}); err != nil {
		t.Fatal(err)
	}
	waitNetworkAttempt(t, repo, 0)
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, body := client.request("GET", "/networks", "", nil)
	if response.StatusCode != 200 || strings.Count(body, `id="network-category-ids"`) != 1 || strings.Count(body, `value="sonet-as2527"`) != 1 || strings.Count(body, `data-filter-page-size="10"`) != 2 || !strings.Contains(body, `data-filter-text="ソニー`) || strings.Count(body, `class="network-row"`) != len(defaultNetworkSources())+len(defaultNetworkCategories()) {
		t.Fatal("large network page not compact or searchable", response.StatusCode)
	}
	if len(body) > 2<<20 {
		t.Fatal("network editor grew quadratically", len(body))
	}
	fields := pageFields(body)
	values := url.Values{"action": {"source_save"}, "index": {"100"}, "preset": {"asn"}, "display_preset": {"missing-category"}, "name": {"保持する入力"}, "asn": {"2510"}, "url": {""}, "kind": {"unknown"}, "label": {""}, "suffix": {""}, "csrf": {fields.Get("csrf")}, "revision": {fields.Get("revision")}, "request_id": {domain.NewID().String()}}
	response, body = client.request("POST", "/networks", values.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 422 || !strings.Contains(body, `value="保持する入力"`) || !strings.Contains(body, `value="missing-category"`) {
		t.Fatal("invalid input lost", response.StatusCode)
	}
	if path := os.Getenv("OIMO_NETWORK_PAGE_OUTPUT"); path != "" {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
