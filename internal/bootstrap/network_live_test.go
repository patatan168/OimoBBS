// 明示実行時だけ無料の公開配信元との接続・現在の形式を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/netip"
	"oimobbs/internal/strictjson"
	"os"
	"testing"
	"time"
)

func TestNetworkLivePublicFeed(t *testing.T) {
	if os.Getenv("OIMO_NETWORK_LIVE") != "1" {
		t.Skip("explicit public-network verification only")
	}
	client := newNetworkClient()
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	sources := []NetworkSource{}
	for _, p := range networkSourcePresets {
		sources = append(sources, NetworkSource{Name: p.Name, Type: "asn", ASN: p.ASN, Kind: p.Kind, Label: p.Label, Suffix: p.Suffix, Provider: presetProvider(p.ID)})
	}
	rows, e := fetchNetworkRows(ctx, client, sources)
	if e != nil || len(rows) == 0 {
		t.Fatal(len(rows), e)
	}
	t.Logf("public provider feeds: %d sources, %d validated prefixes", len(sources), len(rows))
}

// TestNetworkAccessLivePublicFeeds は日本表とVPN専用の両familyを実取得し、保存形式の容量も検査する。
func TestNetworkAccessLivePublicFeeds(t *testing.T) {
	if os.Getenv("OIMO_NETWORK_LIVE") != "1" {
		t.Skip("explicit public-network verification only")
	}
	client := newNetworkClient()
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	data, e := fetchAccessData(ctx, client, defaultAccessSources())
	if e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(data)
	if e != nil || len(raw) > strictjson.MaxBytes-128<<10 {
		t.Fatal("saved data too large", len(raw), e)
	}
	var restored networkAccessData
	if e = strictjson.Decode(raw, &restored); e != nil {
		t.Fatal(e)
	}
	table, count, e := decodeCountries(data.Countries)
	if e != nil || count == 0 {
		t.Fatal(count, e)
	}
	code, _, ok := table.Match(netip.MustParseAddr("8.8.8.8"))
	if !ok || code != "US" {
		t.Fatal("country lookup", code, ok)
	}
	t.Logf("public country prefixes: %d", count)
	t.Logf("public access feeds: Japan %d, VPN IPv4 %d, VPN IPv6 %d, saved JSON %d bytes", len(data.Japan), len(data.VPN4), len(data.VPN6), len(raw))
}

// TestNetworkDomesticLiveStartup は初回設定・国/VPNを含む実取得・耐久保存・再読込をまとめて確認する。
func TestNetworkDomesticLiveStartup(t *testing.T) {
	if os.Getenv("OIMO_NETWORK_LIVE") != "1" {
		t.Skip("explicit public-network verification only")
	}
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "国内回線取得検証"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	repo.networkClient = newNetworkClient()
	defer repo.networkClient.CloseIdleConnections()
	if err = repo.EnsureStandardNetworks(nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if err = repo.refreshNetworks(ctx, true); err != nil {
		t.Fatal(err)
	}
	view, err := repo.networkView()
	if err != nil || view.Error != "" || view.Count == 0 || view.CountryCount == 0 || view.JapanCount == 0 || view.VPN4Count == 0 || view.VPN6Count == 0 || view.AppliedVersion != view.Version {
		t.Fatal("incomplete domestic startup", err)
	}
	t.Logf("%d sources; provider %d, country %d, Japan %d, VPN4 %d, VPN6 %d prefixes", len(view.Config.Sources), view.Count, view.CountryCount, view.JapanCount, view.VPN4Count, view.VPN6Count)
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	saved, err := restored.networkView()
	if err != nil || saved.Count != view.Count || saved.Attempt != view.Attempt || saved.CountryCount != view.CountryCount || saved.Error != "" {
		t.Fatal("live startup not durable", err)
	}
}
