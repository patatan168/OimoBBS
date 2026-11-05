// 回線分類の更新操作を実際の管理HTTPサーバーへ接続したブラウザーで検証する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/identity"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestNetworkCatalogueBrowser は正常な旧標準設定から更新・再描画・手動上書きの保持まで検査する。
// OIMO_NETWORK_LIVE=1の場合、ブラウザーのボタンから公開データを実取得する。
func TestNetworkCatalogueBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザー検証を有効化")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	manual := identity.NetworkClass{CIDR: "192.0.2.42/32", Kind: "business", Label: "手動保持", Suffix: "C", Provider: "custom"}
	repo.mu.Lock()
	state, err := loadNetworkState(repo.site.State())
	if err == nil {
		state.Version++
		state.Config.Enabled = false
		state.Config.Overrides = []identity.NetworkClass{manual}
		for _, previous := range networkBaseSourcePresets {
			state.Config.Sources = append(state.Config.Sources, networkPresetSource(previous))
		}
		state.Config.Sources = append(state.Config.Sources, defaultAccessSources()...)
		if os.Getenv("OIMO_NETWORK_LIVE") != "1" {
			repo.networkClient = &http.Client{Transport: networkTestTransport(networkCatalogueBrowserFeed)}
		}
		err = repo.publishNetworks(state, nil, "network_browser_setup", nil)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	repo.cfg.Admin.Transport, repo.cfg.Admin.Origin, repo.cfg.Public.BaseURL = "public_path", origin+"/admin", origin
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = admin.Handler
	server.Start()
	script, err := filepath.Abs("../../scripts/test-network-catalogue-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_NETWORK_BROWSER_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
	view, err := repo.networkView()
	if err != nil || view.Error != "" || view.Count == 0 || view.AppliedVersion != view.Version || len(view.Config.Overrides) != 1 || view.Config.Overrides[0] != manual {
		t.Fatal("browser update not applied or manual override changed", err, view)
	}
}

// networkCatalogueBrowserFeed は公開フィードと同じ形式の架空データを隔離試験へ返す。
func networkCatalogueBrowserFeed(request *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	switch {
	case strings.HasSuffix(request.URL.Path, "/refs/heads/master"):
		writeCountryFixture(w)
	case strings.HasSuffix(request.URL.Path, "/country/jp/jp.json"):
		fmt.Fprint(w, `{"countryCode":"JP","prefixes":{"ipv4":["1.1.0.0/16"],"ipv6":["2400::/32"]}}`)
	case strings.HasSuffix(request.URL.Path, "/output/vpn/ipv4.txt"):
		fmt.Fprint(w, "2.2.0.0/16\n")
	case strings.HasSuffix(request.URL.Path, "/output/vpn/ipv6.txt"):
		fmt.Fprint(w, "2600::/32\n")
	default:
		var asn uint32
		fmt.Sscanf(request.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn)
		for i, preset := range networkSourcePresets {
			if preset.ASN == asn {
				fmt.Fprintf(w, `{"asn":%d,"prefixes":{"ipv4":["198.18.%d.0/24"],"ipv6":[]}}`, asn, i)
				return w.Result(), nil
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}
	return w.Result(), nil
}
