// 同一の公開配信byteを再生し、分類更新のCPU・割当て・耐久保存を比較する。
package bootstrap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// networkFixtureClient は明示した保存先だけを使う。通常試験では外部取得を行わない。
func networkFixtureClient(t testing.TB) *http.Client {
	t.Helper()
	dir := os.Getenv("OIMO_NETWORK_FIXTURE")
	if dir == "" {
		t.Skip("requires recorded network fixture")
	}
	base := newNetworkClient()
	t.Cleanup(base.CloseIdleConnections)
	return &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		path := filepath.Join(dir, fmt.Sprintf("%x.body", sha256.Sum256([]byte(req.URL.String()))))
		raw, err := os.ReadFile(path)
		if os.IsNotExist(err) && os.Getenv("OIMO_NETWORK_RECORD") == "1" {
			res, e := base.Do(req)
			if e != nil {
				return nil, e
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("fixture status %d for %s", res.StatusCode, req.URL)
			}
			raw, err = io.ReadAll(io.LimitReader(res.Body, (4<<20)+1))
			if err == nil && len(raw) <= 4<<20 {
				err = os.WriteFile(path, raw, 0600)
			}
		}
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: make(http.Header), Request: req}, nil
	})}
}

func TestNetworkRecordFixture(t *testing.T) {
	client := networkFixtureClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	rows, err := fetchNetworkRows(ctx, client, defaultNetworkSources())
	if err != nil {
		t.Fatal(err)
	}
	access, err := fetchAccessData(ctx, client, defaultNetworkSources())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Rows   networkRows
		Access *networkAccessData
	}{rows, access})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("rows=%d japan=%d vpn4=%d vpn6=%d saved=%d sha256=%x", len(rows), len(access.Japan), len(access.VPN4), len(access.VPN6), len(raw), sha256.Sum256(raw))
	country, err := decompressNetworkData(access.Countries, countryUnpackedLimit)
	if err != nil {
		t.Fatal(err)
	}
	semantic, err := json.Marshal(struct {
		Rows              []identity.NetworkClass
		Country           []byte
		Japan, VPN4, VPN6 []string
	}{rows, country, access.Japan, access.VPN4, access.VPN6})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("semantic sha256=%x", sha256.Sum256(semantic))

}

func BenchmarkNetworkUpdate(b *testing.B) {
	client := networkFixtureClient(b)
	for _, kind := range []string{"prepare", "durable", "durable_cold"} {
		b.Run(kind, func(b *testing.B) {
			cfg := testConfig(b)
			if _, err := Initialize(cfg, "分類更新の計測"); err != nil {
				b.Fatal(err)
			}
			r, err := OpenRepository(cfg)
			if err != nil {
				b.Fatal(err)
			}
			defer r.Close()
			r.networkClient = client
			if err = r.EnsureStandardNetworks(nil); err != nil {
				b.Fatal(err)
			}
			// 二回目以降の更新でも旧表の復号・検査を含める。
			if err = r.refreshNetworks(b.Context(), true); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if kind == "durable" || kind == "durable_cold" {
					if kind == "durable_cold" {
						networkCountryCompression = networkCompressionCache{}
						networkRowCompression = networkCompressionCache{}
						networkConfigCompression = networkCompressionCache{}
						networkPrefixCompression = networkCompressionCache{}
						compiledNetworkAccess = networkAccessCache{}
						decodedNetworkRows = networkRowsCache{}
					}

					if err = r.refreshNetworks(b.Context(), true); err != nil {
						b.Fatal(err)
					}
					continue
				}
				rows, access, e := fetchNetworkUpdate(b.Context(), client, defaultNetworkSources())
				if e != nil {
					b.Fatal(e)
				}
				if _, e = json.Marshal(struct {
					Rows   networkRows
					Access *networkAccessData
				}{rows, access}); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}

// TestNetworkRecordedRefreshRecovery は実データ量で失敗時の旧表保持と再起動後の復元を確かめる。
func TestNetworkRecordedRefreshRecovery(t *testing.T) {
	client := networkFixtureClient(t)
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "実データ量の分類更新"); err != nil {
		t.Fatal(err)
	}
	r, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { r.Close() }()
	r.networkClient = client
	if err = r.EnsureStandardNetworks(nil); err != nil {
		t.Fatal(err)
	}
	if err = r.refreshNetworks(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	first, err := loadNetworkState(r.site.State())
	if err != nil {
		t.Fatal(err)
	}
	classifier := r.liveNetworks.Load()
	r.networkClient = &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() == japanNetworkURL {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader([]byte(`{"invalid":true}`)))}, nil
		}
		return client.Transport.RoundTrip(req)
	})}
	if err = r.refreshNetworks(t.Context(), true); err == nil {
		t.Fatal("一部成功を公開した")
	}
	failed, err := loadNetworkState(r.site.State())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Rows, failed.Rows) || !reflect.DeepEqual(first.AccessData, failed.AccessData) || failed.LastSuccess != first.LastSuccess || failed.Error != "invalid_data" || r.liveNetworks.Load() != classifier {
		t.Fatal("取得失敗で前回表を失った")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := loadNetworkState(r.site.State())
	if err != nil || !reflect.DeepEqual(restored, failed) {
		t.Fatal("再起動後に表が変化した", err)
	}
	t.Logf("full refresh, failed refresh and recovery: rows=%d", len(restored.Rows))
}

// TestNetworkDeploymentRefresh は復元した隔離volumeだけで、固定した実配信表への更新と全投稿検査を行う。
func TestNetworkDeploymentRefresh(t *testing.T) {
	path := os.Getenv("OIMO_NETWORK_REHEARSAL_CONFIG")
	if path == "" {
		t.Skip("requires isolated restored volume")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { r.Close() }()
	if r.networkCancel != nil {
		r.networkCancel()
		<-r.networkDone
	}
	before, err := loadNetworkState(r.site.State())
	if err != nil {
		t.Fatal(err)
	}
	r.networkClient = networkFixtureClient(t)
	started := time.Now()
	if err = r.refreshNetworks(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(started)
	after, err := loadNetworkState(r.site.State())
	if err != nil || after.Version != before.Version || !reflect.DeepEqual(after.Config, before.Config) || after.Error != "" || after.LastSuccess <= before.LastSuccess {
		t.Fatal("設定または更新状態が不正", err)
	}
	raw := r.site.State().Rows["network:active"].Value
	if !networkStateZstd(raw, after) {
		t.Fatal("新codecへ更新されなかった")
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OIMO_NETWORK_REHEARSAL_UPDATE_ONLY") == "1" {
		t.Logf("isolated update-only PASS: sources=%d rows=%d saved=%d update=%s", len(after.Config.Sources), len(after.Rows), len(raw), elapsed)
		return
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("全投稿を含む再起動検査", err)
	}
	t.Logf("isolated update and posting recovery PASS: sources=%d rows=%d saved=%d update=%s", len(after.Config.Sources), len(after.Rows), len(raw), elapsed)
}

// TestNetworkRecordedExtendedManagement は1MiBを超える実国表付き状態で、管理変更・再送・復元を確認する。
func TestNetworkRecordedExtendedManagement(t *testing.T) {
	client := networkFixtureClient(t)
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	access, err := fetchAccessData(t.Context(), client, defaultAccessSources())
	if err != nil {
		t.Fatal(err)
	}
	next := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: networkRows{}, AccessData: access, LastAttempt: 1, LastSuccess: 1, AttemptVersion: 1, AppliedVersion: 1}
	next.Config.Sources = defaultAccessSources()
	for i := 0; i < 12000; i++ {
		cidr := fmt.Sprintf("198.18.%d.%d/32", i/256, i%256)
		provider := fmt.Sprintf("%x", sha256.Sum256([]byte(cidr)))
		next.Rows = append(next.Rows, identity.NetworkClass{CIDR: cidr, Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: provider})
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) <= strictjson.MaxBytes || len(raw) > store.MaxNetworkValueJSON {
		t.Fatal("拡張サイズのfixtureにならない", len(raw), err)
	}
	r.mu.Lock()
	err = r.publishNetworks(next, nil, "network_refresh", nil)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	get, _ := c.request("GET", "/api/v1/networks", "", nil)
	next.Config.IntervalHours++
	config, _ := json.Marshal(next.Config)
	headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"extended-network-config-01"}}
	for i := 0; i < 2; i++ {
		res, body := c.request("PATCH", "/api/v1/networks", string(config), headers)
		if res.StatusCode != 200 || i == 1 && !strings.Contains(body, `"duplicate":true`) {
			t.Fatal("大きい保存値の管理変更・再送", res.StatusCode, body)
		}
	}
	saved, err := loadNetworkState(r.site.State())
	if err != nil || saved.Version != 2 || saved.Config.IntervalHours != next.Config.IntervalHours || len(saved.Rows) != len(next.Rows) {
		t.Fatal("管理変更の保存", err)
	}
	c.server.Close()
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	r, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("拡張状態の管理変更から復元できない", err)
	}
	t.Logf("extended management, duplicate and recovery PASS: saved=%d", len(raw))
}
