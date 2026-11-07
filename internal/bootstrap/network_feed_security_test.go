// 外部取得元の件数過多を検査し、拒否までの割当てを同じ入力で比較する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"oimobbs/internal/postcapture"
	"reflect"
	"sync/atomic"
	"testing"
)

// networkFeedPrefixes は外部通信を使わず、重複しない検証用IPv4 prefixを作る。
func networkFeedPrefixes(count int) []string {
	values := make([]string, count)
	for i := range values {
		values[i] = fmt.Sprintf("10.%d.%d.%d/32", i>>16, i>>8&255, i&255)
	}
	return values
}

// networkASNBody は実際のASN取得と同じJSON形式を合成する。
func networkASNBody(t testing.TB, v4, v6 []string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"asn": 9605, "prefixes": map[string]any{"ipv4": v4, "ipv6": v6}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// networkFeedBodyClient は取得先URLの検査を維持し、合成本文だけを返す。
func networkFeedBodyClient(raw []byte) *http.Client {
	return &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: req}, nil
	})}
}

// TestNetworkFeedRowBoundaries は上限ちょうどの受理と、両family合計・VPNの超過拒否を確認する。
func TestNetworkFeedRowBoundaries(t *testing.T) {
	source := NetworkSource{Name: "fixture", Type: "asn", ASN: 9605, Kind: "fixed", Label: "固定", Suffix: "0"}
	v4 := networkFeedPrefixes(networkRowLimit + 1)
	for _, count := range []int{networkRowLimit, networkRowLimit + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			rows, err := parseASNNetworks(networkASNBody(t, v4[:count], []string{}), source)
			if count == networkRowLimit {
				if err != nil || len(rows) != count {
					t.Fatalf("valid ASN boundary: rows=%d err=%v", len(rows), err)
				}
			} else if !errors.Is(err, errNetworkData) || rows != nil {
				t.Fatalf("oversized ASN table: rows=%d err=%v", len(rows), err)
			}
			body := []byte("# fixture\n\n")
			for _, prefix := range v4[:count] {
				body = append(body, prefix...)
				body = append(body, '\n')
			}
			values, err := fetchVPNPrefixes(t.Context(), networkFeedBodyClient(body), true)
			if count == networkRowLimit {
				if err != nil || len(values) != count {
					t.Fatalf("valid VPN boundary: rows=%d err=%v", len(values), err)
				}
			} else if !errors.Is(err, errNetworkData) || values != nil {
				t.Fatalf("oversized VPN table: rows=%d err=%v", len(values), err)
			}
		})
	}
	if rows, err := parseASNNetworks(networkASNBody(t, v4[:networkRowLimit], []string{"2001:db8::/32"}), source); !errors.Is(err, errNetworkData) || rows != nil {
		t.Fatalf("combined family limit: rows=%d err=%v", len(rows), err)
	}
}

// TestNetworkOversizedFeedPreservesPublishedState は実TLS取得で超過を拒否し、前回表と再起動後の状態を守る。
func TestNetworkOversizedFeedPreservesPublishedState(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			_ = repo.Close()
		}
	}()
	values := networkFeedPrefixes(networkRowLimit + 1)
	valid := networkASNBody(t, values[:1], []string{})
	oversized := networkASNBody(t, values, []string{})
	var attack atomic.Bool
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := valid
		if attack.Load() {
			body = oversized
		}
		_, _ = w.Write(body)
	}))
	defer feed.Close()
	repo.mu.Lock()
	state, err := loadNetworkState(repo.site.State())
	if err == nil {
		state.Version++
		state.Config.Enabled = false
		state.Config.Sources = []NetworkSource{{Name: "fixture", Type: "asn", ASN: 9605, Kind: "fixed", Label: "固定", Suffix: "0"}}
		err = repo.publishNetworks(state, nil, "network_config", nil)
	}
	repo.networkClient = networkTestClient(feed)
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.refreshNetworks(t.Context(), true); err != nil {
		t.Fatal("valid feed control", err)
	}
	before, err := loadNetworkState(repo.site.State())
	if err != nil || len(before.Rows) != 1 {
		t.Fatal("valid feed not published", err)
	}
	classifier := repo.liveNetworks.Load()
	attack.Store(true)
	if err := repo.refreshNetworks(t.Context(), true); !errors.Is(err, errNetworkData) {
		t.Fatal("oversized feed not rejected", err)
	}
	after, err := loadNetworkState(repo.site.State())
	if err != nil || after.Error != "invalid_data" || after.LastSuccess != before.LastSuccess || !reflect.DeepEqual(after.Rows, before.Rows) || repo.liveNetworks.Load() != classifier {
		t.Fatal("rejected feed changed last successful classification", err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := loadNetworkState(repo.site.State())
	actual := repo.liveNetworks.Load().Classify(nil, netip.MustParseAddr("10.0.0.0"))
	if err != nil || restored.Error != "invalid_data" || !reflect.DeepEqual(restored.Rows, before.Rows) || actual.Kind != "fixed" {
		t.Fatal("rejected feed lost successful state on restart", err, actual)
	}
}

// BenchmarkNetworkOversizedFeeds はbyte上限内でも件数が多い応答の拒否コストを測る。
func BenchmarkNetworkOversizedFeeds(b *testing.B) {
	source := NetworkSource{Name: "fixture", Type: "asn", ASN: 9605, Kind: "fixed", Label: "固定", Suffix: "0"}
	for _, kind := range []string{"asn", "vpn"} {
		b.Run(kind, func(b *testing.B) {
			values := make([]string, 80000)
			for i := range values {
				values[i] = "1.0.0.0/8"
			}
			raw := networkASNBody(b, values, []string{})
			if kind == "vpn" {
				raw = bytes.Repeat([]byte("1.0.0.0/8\n"), 320000)
			}
			client := networkFeedBodyClient(raw)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for b.Loop() {
				var err error
				if kind == "asn" {
					_, err = parseASNNetworks(raw, source)
				} else {
					_, err = fetchVPNPrefixes(b.Context(), client, true)
				}
				if !errors.Is(err, errNetworkData) {
					b.Fatalf("oversized feed was not rejected: %v", err)
				}
			}
		})
	}
}
