// 通常の自動更新で標準分類を反映し、停止・更新間隔・競合する手動設定を守ることを検証する。
package bootstrap

import (
	"net/http"
	"net/netip"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// TestNetworkCatalogueAutomaticRefresh は既存の更新可否判断を変えず、取得時だけ標準分類を反映する。
func TestNetworkCatalogueAutomaticRefresh(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		age     time.Duration
		refresh bool
	}{{"scheduled", true, 25 * time.Hour, true}, {"stopped", false, 25 * time.Hour, false}, {"not_due", true, time.Minute, false}} {
		t.Run(tc.name, func(t *testing.T) {
			_, repo := adminFixture(t)
			defer repo.Close()
			manual := identity.NetworkClass{CIDR: "192.0.2.42/32", Kind: "business", Label: "手動保持", Suffix: "C", Provider: "custom"}
			var requests atomic.Int32
			repo.mu.Lock()
			state, err := loadNetworkState(repo.site.State())
			if err == nil {
				state.Version++
				state.Config.Enabled = tc.enabled
				state.Config.Overrides = []identity.NetworkClass{manual}
				for _, preset := range networkBaseSourcePresets {
					if preset.ASN == 9351 {
						state.Config.Sources = []NetworkSource{networkPresetSource(preset)}
						state.Config.Categories = []NetworkCategory{networkPresetCategory(preset)}
					}
				}
				err = repo.publishNetworks(state, nil, "network_config", nil)
			}
			if err == nil {
				state.Rows = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "unknown", Label: "ZLAN", Suffix: "0", Provider: "zlan"}}
				state.LastAttempt = domain.Time(time.Now().Add(-tc.age).UnixNano())
				state.LastSuccess = state.LastAttempt
				state.AttemptVersion, state.AppliedVersion = state.Version, state.Version
				err = repo.publishNetworks(state, nil, "network_refresh", nil)
			}
			repo.networkClient = &http.Client{Transport: networkTestTransport(func(request *http.Request) (*http.Response, error) {
				requests.Add(1)
				return networkCatalogueBrowserFeed(request)
			})}
			revision := repo.site.State().Rows["network:active"].Revision
			repo.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.refreshNetworks(t.Context(), false); err != nil {
				t.Fatal(err)
			}
			after, err := repo.networkView()
			if err != nil || !reflect.DeepEqual(after.Config.Overrides, state.Config.Overrides) || repo.liveNetworks.Load().Classify(nil, netip.MustParseAddr("192.0.2.42")) != manual {
				t.Fatal("manual override changed", err, after)
			}
			if !tc.refresh {
				if after.Revision != revision || requests.Load() != 0 || !reflect.DeepEqual(after.Config, state.Config) {
					t.Fatal("stopped or not-due update changed settings", after)
				}
				return
			}
			if requests.Load() != 1 || after.Config.Sources[0].Kind != "fixed" || after.Config.Categories[0].Kind != "fixed" || after.Version != state.Version+1 || after.AppliedVersion != after.Version || after.Error != "" {
				t.Fatal("automatic refresh did not reclassify", after, requests.Load())
			}
		})
	}
}

// TestNetworkCatalogueRefreshConflict は分類準備中の手動設定変更を古い状態で上書きしないことを検査する。
func TestNetworkCatalogueRefreshConflict(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.mu.Lock()
	old, err := loadNetworkState(repo.site.State())
	if err == nil {
		old.Version++
		old.Config.Sources = []NetworkSource{networkPresetSource(networkBaseSourcePresets[5])}
		err = repo.publishNetworks(old, nil, "network_config", nil)
	}
	snapshot := repo.site.State()
	next := old
	next.Version++
	next.Config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "business", Label: "追加保持", Suffix: "C"}}
	if err == nil {
		err = repo.publishNetworks(next, nil, "network_config", nil)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := repo.prepareNetworkCatalogueRefresh(&snapshot, &old)
	after, viewErr := repo.networkView()
	if fresh || err != nil || viewErr != nil || !reflect.DeepEqual(after.Config, next.Config) {
		t.Fatal("concurrent settings overwritten", fresh, err, viewErr, after)
	}
}
