// 運用画面・APIから手動資源設定を除き、保存済み上限にも制約されないことを検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/platform"
	"strings"
	"testing"
)

func TestOperationsResourcesAreAutomaticOnly(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	// 以前に保存された固定値は、資源計算にも公開する設定にも使わない。
	saved := operationState{Settings: repo.operations()}
	saved.Settings.CacheBytes = 2 << 20
	saved.Settings.CacheWorkers = 1
	repo.liveOperations.Store(&saved)
	repo.memory.Store(&platform.MemoryState{Limit: 12 << 30, Headroom: 8 << 30})
	repo.feedCompression.RefreshResources()
	if status := repo.feedCompression.Status(); status.Limit != 1536<<20 {
		t.Fatal("legacy fixed limit still applies", status)
	}
	response, body := client.request("GET", "/api/v1/operations", "", nil)
	var view struct {
		Data struct {
			Settings map[string]json.RawMessage `json:"settings"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil || response.StatusCode != 200 {
		t.Fatal("view", err, response.StatusCode)
	}
	for _, key := range []string{"cache_bytes", "cache_workers"} {
		if _, ok := view.Data.Settings[key]; ok {
			t.Fatal("manual resource field in API", key)
		}
	}
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {response.Header.Get("ETag")}, "X-CSRF-Token": {response.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"automatic-only-reject"}}
	for _, key := range []string{"cache_bytes", "cache_workers"} {
		invalid := make(map[string]json.RawMessage)
		for k, v := range view.Data.Settings {
			invalid[k] = v
		}
		invalid[key] = json.RawMessage("1")
		raw, _ := json.Marshal(invalid)
		res, _ := client.request("POST", "/api/v1/operations", string(raw), headers)
		if res.StatusCode != 400 {
			t.Fatal("manual resource field accepted", key, res.StatusCode)
		}
	}
	_, page := client.request("GET", "/operations", "", nil)
	fields := pageFields(page)
	if fields.Has("cache_mib") || fields.Has("cache_workers") || !strings.Contains(page, "全自動") {
		t.Fatal("manual resource controls remain")
	}
	// 新しいフォームは手動資源値を送信せず、残る運用設定だけを保存できる。
	settings := repo.operations()
	for name, value := range map[string]string{"maintenance_enabled": "false", "interval_seconds": "300", "max_threads": "5", "max_seconds": "30", "egress_mbps": "80", "window_minutes": "1440", "quorum": "3", "stop_minutes": "10", "report_interval_minutes": "10"} {
		fields.Set(name, value)
	}
	res, body := client.request("POST", "/operations", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("form save", res.StatusCode, body)
	}
	if repo.operations().CacheBytes != 0 || repo.operations().CacheWorkers != 0 || repo.operations().Reports != settings.Reports {
		t.Fatal("fixed settings persisted or reports changed")
	}
}
