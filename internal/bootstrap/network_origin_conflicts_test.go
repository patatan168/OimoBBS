// 複数ASNの分類衝突を不明として保持し、取得順・耐久保存・手動上書きを検証する。
package bootstrap

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"oimobbs/internal/identity"
	"reflect"
	"strings"
	"testing"
)

func TestNetworkOriginConflictsAreOrderIndependent(t *testing.T) {
	for _, cidr := range []string{"151.245.164.0/24", "2001:db8:1::/48"} {
		a := identity.NetworkClass{CIDR: cidr, Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "vultr"}
		b := identity.NetworkClass{CIDR: cidr, Kind: "unknown", Label: "M247", Suffix: "0", Provider: "m247"}
		c := a
		c.Provider = "third"
		want := identity.NetworkClass{CIDR: cidr, Kind: "unknown", Label: "ﾜｯﾁｮｲ", Suffix: "0"}
		for _, order := range [][]identity.NetworkClass{{a, b, c}, {a, c, b}, {b, a, c}, {b, c, a}, {c, a, b}, {c, b, a}} {
			seen := map[string]identity.NetworkClass{}
			batches := []networkBatch{}
			for _, row := range append(order, order...) {
				rows, err := retainNetworkBatch([]identity.NetworkClass{row}, seen)
				if err != nil {
					t.Fatalf("order=%+v: %v", order, err)
				}
				batches = append(batches, networkBatch{rows: rows})
			}
			// 設定順の統合はworker完了順と一致しない。
			for left, right := 0, len(batches)-1; left < right; left, right = left+1, right-1 {
				batches[left], batches[right] = batches[right], batches[left]
			}
			rows, err := mergeNetworkBatches(batches, nil)
			if err != nil || !reflect.DeepEqual(rows, []identity.NetworkClass{want}) || seen[cidr] != want {
				t.Fatalf("order=%+v rows=%+v seen=%+v err=%v", order, rows, seen, err)
			}
		}
	}
}

// originConflictClient は実際に衝突したprefixと、別の正常prefixを含むASN応答を返す。
func originConflictClient(invalid bool) *http.Client {
	return &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		var asn uint32
		if _, err := fmt.Sscanf(req.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn); err != nil {
			return nil, err
		}
		body := fmt.Sprintf(`{"asn":%d,"prefixes":{"ipv4":["151.245.164.0/24"],"ipv6":["2001:db8:1::/48"]}}`, asn)
		if asn == 20473 {
			body = strings.Replace(body, `"151.245.164.0/24"`, `"151.245.0.0/16","151.245.164.0/24","192.0.2.0/24"`, 1)
		}
		if invalid {
			body = `{"invalid":true}`
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
}

func TestNetworkOriginConflictRefreshRecovery(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "ASN分類衝突"); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { r.Close() }()
	config := defaultNetworkConfig()
	config.Sources = []NetworkSource{
		{Name: "Vultr", Type: "asn", ASN: 20473, Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "vultr"},
		{Name: "M247", Type: "asn", ASN: 9009, Kind: "unknown", Label: "M247", Suffix: "0", Provider: "m247"},
	}
	config.Overrides = []identity.NetworkClass{{CIDR: "151.245.164.1/32", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0", Provider: "manual"}}
	r.mu.Lock()
	err = r.publishNetworks(networkState{Version: 1, Config: config, Rows: []identity.NetworkClass{}}, nil, "network_standard_setup", nil)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r.networkClient = originConflictClient(false)
	if err = r.refreshNetworks(t.Context(), true); err != nil {
		t.Fatal("valid multiple origins stopped refresh", err)
	}
	check := func() {
		t.Helper()
		for ip, kind := range map[string]string{"151.245.164.2": "unknown", "2001:db8:1::1": "unknown", "192.0.2.1": "hosting", "151.245.165.1": "hosting", "151.245.164.1": "fixed"} {
			got := r.liveNetworks.Load().Classify(nil, netip.MustParseAddr(ip))
			if got.Kind != kind || kind == "unknown" && (got.Provider != "" || got.Label != "ﾜｯﾁｮｲ" || got.Suffix != "0") {
				t.Fatalf("%s: %+v", ip, got)
			}
		}
	}
	check()
	first, err := loadNetworkState(r.site.State())
	if err != nil || first.Error != "" || first.LastSuccess == 0 {
		t.Fatal("refresh not saved", err)
	}
	r.networkClient = originConflictClient(true)
	if err = r.refreshNetworks(t.Context(), true); err == nil {
		t.Fatal("malformed feed accepted")
	}
	failed, err := loadNetworkState(r.site.State())
	if err != nil || failed.Error != "invalid_data" || failed.LastSuccess != first.LastSuccess || !reflect.DeepEqual(failed.Rows, first.Rows) || !reflect.DeepEqual(failed.Config, config) {
		t.Fatal("failed refresh lost previous table or overrides", err)
	}
	check()
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	check()
	restored, err := loadNetworkState(r.site.State())
	if err != nil || !reflect.DeepEqual(restored, failed) {
		t.Fatal("restart changed saved table", err)
	}
}
