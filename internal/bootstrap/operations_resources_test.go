// 自動設定のHTTP保存・再起動と、小容量から大容量への追従を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/platform"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"testing"
)

func TestOperationsAutomaticResourcesPersistence(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	response, body := client.request("GET", "/api/v1/operations", "", nil)
	var view struct {
		Data operationsTestAPI `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	view.Data.Settings.CacheBytes = 0
	view.Data.Settings.CacheWorkers = 0
	raw, _ := json.Marshal(OperationSettings(view.Data.Settings).editable())
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {response.Header.Get("ETag")}, "X-CSRF-Token": {response.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"operations-automatic-resources"}}
	response, body = client.request("POST", "/api/v1/operations", string(raw), headers)
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	var site siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != reportIntervalReader {
		t.Fatal("reader guard", err, site.MinimumReader)
	}
	client.server.Close()
	repo.Close()
	repo = nil

	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if settings := repo.operations(); settings.CacheWorkers != 0 || settings.CacheBytes != 0 {
		t.Fatal("automatic setting lost", settings)
	}
	repo.memory.Store(&platform.MemoryState{Limit: 192 << 20, Headroom: 128 << 20})
	repo.feedCompression.RefreshResources()
	if s := repo.feedCompression.Status(); s.Limit != 24<<20 || s.Workers < 1 || s.Workers > 3 {
		t.Fatal("small resources", s)
	}
	repo.memory.Store(&platform.MemoryState{Limit: 12 << 30, Headroom: 8 << 30})
	repo.feedCompression.RefreshResources()
	if s := repo.feedCompression.Status(); s.Limit != 1536<<20 {
		t.Fatal("large resources", s)
	}
}
