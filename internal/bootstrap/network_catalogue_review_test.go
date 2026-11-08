// 標準分類の対象上書きと、取得成功後だけ判定・規制へ反映されることを検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestNetworkCatalogueReview はカタログ全体の分類数と、共有基盤を一律分類しない境界を検査する。
func TestNetworkCatalogueReview(t *testing.T) {
	counts := map[string]int{}
	byASN := map[uint32]NetworkSource{}
	for _, source := range defaultNetworkSources() {
		if source.Type == "asn" {
			counts[source.Kind]++
			byASN[source.ASN] = source
		}
	}
	want := map[string]int{"unknown": 87, "fixed": 115, "mixed": 6, "mobile": 2, "academic": 9, "hosting": 16, "satellite": 1, "government": 1}
	if !reflect.DeepEqual(counts, want) {
		t.Fatal("catalogue coverage", counts, want)
	}
	for asn, kind := range map[uint32]string{2497: "mixed", 2518: "mixed", 9351: "fixed", 55391: "fixed", 55392: "fixed", 59104: "academic", 45674: "unknown", 10013: "unknown", 131160: "unknown", 55387: "unknown", 150363: "unknown", 9009: "unknown", 398391: "unknown"} {
		if byASN[asn].Kind != kind {
			t.Fatal(asn, byASN[asn])
		}
	}
	for _, category := range defaultNetworkCategories() {
		if category.ID == "transix" && category.Kind != "unknown" {
			t.Fatal("one reviewed ASN classified the provider's other networks", category)
		}
	}
}

// TestNetworkReclassificationOverwrite は対象の独自編集も上書きし、対象外と入力の不変性を検査する。
func TestNetworkReclassificationOverwrite(t *testing.T) {
	config := defaultNetworkConfig()
	config.IntervalHours = 72
	config.DNSMode = "google_https"
	config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "business", Label: "独自", Suffix: "C"}}
	config.AccessOverrides = []identity.AccessOverride{{CIDR: "192.0.2.0/24", Country: "jp", VPN: "direct"}}
	for _, previous := range networkBaseSourcePresets {
		config.Sources = append(config.Sources, networkPresetSource(previous))
	}
	config.Categories = []NetworkCategory{networkPresetCategory(networkBaseSourcePresets[0])}
	// ZTVの旧標準を使い、各項目が編集されている場合をそれぞれ確認する。
	var previous networkPreset
	for _, preset := range networkBaseSourcePresets {
		if preset.ASN == 9351 {
			previous = preset
		}
	}
	old := networkPresetSource(previous)
	edits := []NetworkSource{old, old, old, old, old}
	edits[0].Name = "独自名称"
	edits[1].Kind = "business"
	edits[2].Label = "独自表示"
	edits[3].Suffix = "Z"
	edits[4].Provider = "custom"
	for _, edited := range edits {
		only := config
		only.Sources = []NetworkSource{edited}
		only.Categories = []NetworkCategory{networkPresetCategory(previous)}
		only.Categories[0].Description = "独自の説明"
		next := reclassifyStandardNetworks(only)
		if next.Sources[0].Kind != "fixed" || next.Sources[0].Name != "ZTV CO. LTD（AS9351・固定推定）" || next.Sources[0].Label != "ﾜｯﾁｮｲ" || next.Sources[0].Suffix != "0" || next.Sources[0].Provider != "zlan" || next.Categories[0].Description == "独自の説明" {
			t.Fatal("reviewed source edit not overwritten", next)
		}
	}
	config.Categories = append(config.Categories, networkPresetCategory(previous))
	config.Sources[0].Name = "対象外の独自名称"
	snapshot, _ := json.Marshal(config)
	next := reclassifyStandardNetworks(config)
	err := next.validate()
	if err != nil || next.Enabled || next.IntervalHours != 72 || next.DNSMode != config.DNSMode || !reflect.DeepEqual(next.Overrides, config.Overrides) || !reflect.DeepEqual(next.AccessOverrides, config.AccessOverrides) || len(next.Sources) != len(config.Sources) {
		t.Fatal("settings changed", err, next)
	}
	wantSource, wantCategory := config.Sources[0], config.Categories[0]
	wantSource.Label, wantCategory.Label = "ｵｼﾏｾﾞ", "ｵｼﾏｾﾞ"
	if next.Sources[0] != wantSource || next.Categories[0] != wantCategory {
		t.Fatal("display repair changed other fields")
	}
	if next.Categories[1].Kind != "fixed" || next.Categories[1].Label != "ﾜｯﾁｮｲ" {
		t.Fatal("standard category not updated", next.Categories)
	}
	after, _ := json.Marshal(config)
	if string(snapshot) != string(after) || !reflect.DeepEqual(next, reclassifyStandardNetworks(next)) {
		t.Fatal("input mutated or repeated operation changed settings")
	}
}

// TestNetworkReclassificationHTTP は通常フォームから失敗時の旧表保持・成功時の分類・再起動まで確認する。
func TestNetworkReclassificationHTTP(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	var failed atomic.Bool
	repo.mu.Lock()
	repo.networkClient = &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		if failed.Load() {
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable"))}, nil
		}
		var asn uint32
		fmt.Sscanf(req.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn)
		body := fmt.Sprintf(`{"asn":%d,"prefixes":{"ipv4":["192.0.2.0/24"],"ipv6":["2001:db8::/32"]}}`, asn)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	repo.mu.Unlock()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	config := defaultNetworkConfig()
	manual := identity.NetworkClass{CIDR: "192.0.2.42/32", Kind: "business", Label: "手動", Suffix: "C", Provider: "custom"}
	config.Overrides = []identity.NetworkClass{manual}
	for _, previous := range networkBaseSourcePresets {
		if previous.ASN == 9351 {
			config.Sources = []NetworkSource{networkPresetSource(previous)}
			config.Categories = []NetworkCategory{networkPresetCategory(previous)}
		}
	}
	get, _ := client.request("GET", "/api/v1/networks", "", nil)
	raw, _ := json.Marshal(config)
	response, body := client.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"before-reclassification"}})
	if response.StatusCode != 200 {
		t.Fatal("legacy setup", response.StatusCode, body)
	}
	// 再分類導入前に成功した表を復元し、失敗時にその表を保持することを検査する。
	repo.mu.Lock()
	legacy, err := loadNetworkState(repo.site.State())
	if err == nil {
		legacy.Rows = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "unknown", Label: "ZLAN", Suffix: "0", Provider: "zlan"}, {CIDR: "2001:db8::/32", Kind: "unknown", Label: "ZLAN", Suffix: "0", Provider: "zlan"}}
		legacy.LastAttempt = domain.Time(time.Now().UnixNano())
		legacy.LastSuccess = legacy.LastAttempt
		legacy.AttemptVersion, legacy.AppliedVersion = legacy.Version, legacy.Version
		err = repo.publishNetworks(legacy, nil, "network_refresh", nil)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before, _ := repo.networkView()
	_, body = client.request("GET", "/networks", "", nil)
	if strings.Contains(body, "standard_reclassify") || !strings.Contains(body, "今すぐ更新") {
		t.Fatal("unexpected action")
	}
	fields := pageFields(body)
	form := url.Values{"action": {"refresh"}, "csrf": {fields.Get("csrf")}, "revision": {fields.Get("revision")}, "request_id": {"refresh-standard"}}
	failed.Store(true)
	response, body = client.request("POST", "/networks", form.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 {
		t.Fatal("reclassify form", response.StatusCode, body)
	}
	view := waitNetworkAttempt(t, repo, before.Attempt)
	if view.Config.Enabled || view.Config.Sources[0].Kind != "fixed" || view.Error != "fetch_failed" || view.LastSuccess != before.LastSuccess || view.AppliedVersion != before.AppliedVersion {
		t.Fatal("failed refresh changed table or settings", view)
	}
	ip := netip.MustParseAddr("192.0.2.1")
	policy := &NetworkAccessSettings{AllowVPN: true, DeniedKinds: []string{"fixed"}}
	if repo.liveNetworks.Load().Classify(nil, ip).Kind != "unknown" || checkNetworkPermission(repo.liveNetworks.Load(), policy, ip) != nil {
		t.Fatal("failed fetch published new classification")
	}
	failed.Store(false)
	if err := repo.refreshNetworks(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		ip := netip.MustParseAddr(address)
		if repo.liveNetworks.Load().Classify(nil, ip).Kind != "fixed" || checkNetworkPermission(repo.liveNetworks.Load(), policy, ip) != ErrNetworkPermission {
			t.Fatal("new classification not used for access", address)
		}
	}
	if repo.liveNetworks.Load().Classify(nil, netip.MustParseAddr("192.0.2.42")) != manual {
		t.Fatal("manual IP override replaced by reviewed source")
	}
	boardOverride := identity.NetworkClass{CIDR: "192.0.2.42/32", Kind: "mvno", Label: "板別", Suffix: "M", Provider: "board-custom"}
	if repo.liveNetworks.Load().Classify([]identity.NetworkClass{boardOverride}, netip.MustParseAddr("192.0.2.42")) != boardOverride {
		t.Fatal("board override lost priority")
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	view, err = repo.networkView()
	if err != nil || view.Config.Enabled || view.Config.Categories[0].Kind != "fixed" || repo.liveNetworks.Load().Classify(nil, ip).Kind != "fixed" || !reflect.DeepEqual(view.Config.Overrides, config.Overrides) || repo.liveNetworks.Load().Classify(nil, netip.MustParseAddr("192.0.2.42")) != manual {
		t.Fatal("reclassification not durable", err, view)
	}
}
