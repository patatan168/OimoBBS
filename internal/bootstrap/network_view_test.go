// 大きな分類表の画面配信量と、集計再利用後の更新反映・返却値の独立性を検証する。
package bootstrap

import (
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"testing"
	"time"
)

// largeNetworkViewFixture は圧縮保存される実際の形式で1万2千行の分類表を用意する。
func largeNetworkViewFixture(t *testing.T) (*Repository, networkState) {
	t.Helper()
	_, repo := adminFixture(t)
	t.Cleanup(func() { repo.Close() })
	repo.mu.Lock()
	defer repo.mu.Unlock()
	state, err := loadNetworkState(repo.site.State())
	if err != nil {
		t.Fatal(err)
	}
	state.Version = max(state.Version, 1)
	state.LastAttempt, state.LastSuccess, state.AttemptVersion, state.AppliedVersion = 1, 1, state.Version, state.Version
	for i := range 12000 {
		state.Rows = append(state.Rows, identity.NetworkClass{CIDR: fmt.Sprintf("198.18.%d.%d/32", i/256, i%256), Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "cloud"})
	}
	if err = repo.publishNetworks(state, nil, "network_refresh", nil); err != nil {
		t.Fatal(err)
	}
	return repo, state
}

func TestNetworkLargePageDelivery(t *testing.T) {
	repo, _ := largeNetworkViewFixture(t)
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	start := time.Now()
	res, body := c.request("GET", "/networks", "", nil)
	htmlTime := time.Since(start)
	if res.StatusCode != 200 {
		t.Fatal("networks HTML", res.StatusCode)
	}
	assets := requireAdminPageAssets(t, body, "favicon.svg", "ui.css", "admin.css", "ui.js", "admin.js", "admin-networks.css", "list.css", "list.js", "admin-networks.js")
	start = time.Now()
	for _, asset := range assets {
		res, body = c.request("GET", asset, "", nil)
		if res.StatusCode != 200 || body == "" || res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("network asset", res.StatusCode)
		}
	}
	t.Logf("12000 rows: HTML=%s, all %d assets=%s", htmlTime, len(assets), time.Since(start))
}

func TestNetworkViewFreshnessAndIsolation(t *testing.T) {
	repo, state := largeNetworkViewFixture(t)
	first, err := repo.networkView()
	if err != nil || first.Count != 12000 {
		t.Fatal("initial count", err, first.Count)
	}
	original := first.Config.Categories[0].Name
	first.Config.Categories[0].Name = "変更した返却値"
	repo.networkRunning.Store(true)
	second, err := repo.networkView()
	if err != nil || !second.Running || second.Config.Categories[0].Name != original {
		t.Fatal("shared mutable config or stale running", err)
	}
	repo.networkRunning.Store(false)
	state.LastAttempt = 2
	state.Error = "fetch_failed"
	repo.mu.Lock()
	err = repo.publishNetworks(state, nil, "network_refresh", nil)
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := repo.networkView()
	if err != nil || updated.Running || updated.Attempt != 2 || updated.Error != "fetch_failed" || updated.Revision == second.Revision || updated.Count != 12000 {
		t.Fatal("stale update", err, updated.Attempt, updated.Revision, updated.Error)
	}
}

// TestNetworkViewConcurrentPublication は集計中の版切替でも新しい行を古いキャッシュで覆わないことを確認する。
func TestNetworkViewConcurrentPublication(t *testing.T) {
	repo, state := largeNetworkViewFixture(t)
	done := make(chan error, 1)
	go func() {
		for range 8 {
			view, err := repo.networkView()
			if err != nil {
				done <- err
				return
			}
			if view.Count != 12000 || view.Attempt < 1 || view.Attempt > 3 {
				done <- fmt.Errorf("invalid concurrent view: count=%d attempt=%d", view.Count, view.Attempt)
				return
			}
		}
		done <- nil
	}()
	for _, attempt := range []int64{2, 3} {
		state.LastAttempt = domain.Time(attempt)
		repo.mu.Lock()
		err := repo.publishNetworks(state, nil, "network_refresh", nil)
		repo.mu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	view, err := repo.networkView()
	if err != nil || view.Attempt != 3 {
		t.Fatal("old view replaced the latest revision", view.Attempt, err)
	}
}
