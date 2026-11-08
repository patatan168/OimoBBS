// 更新予定の通常フォーム・API・旧設定読込・再起動・reader境界を検証する。
package bootstrap

import (
	"encoding/json"
	"maps"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestNetworkScheduleAutomaticFetch は期限到来・失敗を含め各回1度だけ自動取得し、次回を待つ。
func TestNetworkScheduleAutomaticFetch(t *testing.T) {
	for _, failed := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[failed], func(t *testing.T) {
			_, repo := adminFixture(t)
			defer repo.Close()
			// 起動時の更新と競合させず、この試験から各予定の取得を明示的に実行する。
			repo.networkCancel()
			<-repo.networkDone
			var requests atomic.Int32
			now := time.Now().In(domain.JST)
			// 直前の暦日に設定済みで、現在の分の予定は未実行。時計待ちは不要。
			repo.mu.Lock()
			state, err := loadNetworkState(repo.site.State())
			if err == nil {
				state.Version++
				state.Config.Enabled = true
				state.Config.Sources = defaultNetworkSources()[:1]
				state.Config.Schedule = &NetworkSchedule{Frequency: "daily", Time: now.Format("15:04"), StartsAt: domain.Time(now.AddDate(0, 0, -1).UnixNano())}
				err = repo.publishNetworks(state, nil, "network_config", nil)
			}
			repo.networkClient = &http.Client{Transport: networkTestTransport(func(r *http.Request) (*http.Response, error) {
				requests.Add(1)
				response, err := networkCatalogueBrowserFeed(r)
				if failed {
					response.StatusCode = http.StatusServiceUnavailable
				}
				return response, err
			})}
			repo.mu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := repo.refreshNetworks(t.Context(), false); (err != nil) != failed {
				t.Fatal("unexpected fetch result", failed, err)
			}
			first, err := repo.networkView()
			if err != nil || first.Attempt <= 0 || requests.Load() != 1 || (first.Error != "") != failed {
				t.Fatal("due update not attempted", first, err, requests.Load())
			}
			if next, err := time.Parse(time.RFC3339, first.NextUpdate); err != nil || !next.After(now) {
				t.Fatal("next slot not advanced", first.NextUpdate, err)
			}
			if err := repo.refreshNetworks(t.Context(), false); err != nil {
				t.Fatal(err)
			}
			second, err := repo.networkView()
			if err != nil || second.Revision != first.Revision || requests.Load() != 1 {
				t.Fatal("same period retried", second, err, requests.Load())
			}
		})
	}
}

// TestNetworkScheduleSettingsRecovery は保存だけでは取得せず、手動更新と復旧でも予定・上書きを保持する。
func TestNetworkScheduleSettingsRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	var requests atomic.Int32
	repo.mu.Lock()
	repo.networkClient = &http.Client{Transport: networkTestTransport(func(r *http.Request) (*http.Response, error) { requests.Add(1); return networkCatalogueBrowserFeed(r) })}
	repo.mu.Unlock()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	config := defaultNetworkConfig()
	config.Sources = defaultNetworkSources()[:1]
	config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.42/32", Kind: "business", Label: "手動保持", Suffix: "C"}}
	get, _ := client.request("GET", "/api/v1/networks", "", nil)
	raw, _ := json.Marshal(config)
	response, body := client.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"schedule-source-0001"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	_, body = client.request("GET", "/networks", "", nil)
	hidden := pageFields(body)
	fields := url.Values{"action": {"settings"}, "enabled": {"true"}, "interval_hours": {"24"}, "dns_mode": {"system"}, "schedule_mode": {"weekly"}, "schedule_time": {"04:00"}, "schedule_weekday": {"1"}, "schedule_day": {"1"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"weekly-settings-0001"}}
	response, body = client.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 || strings.Contains(body, "data-network-poll") {
		t.Fatal("schedule save started fetch", response.StatusCode, body)
	}
	view, err := repo.networkView()
	if err != nil || view.Config.Schedule == nil || view.Config.Schedule.Frequency != "weekly" || view.Config.Schedule.Time != "04:00" || view.Config.Schedule.StartsAt <= 0 || requests.Load() != 0 {
		t.Fatal(view, err, requests.Load())
	}
	next, err := time.Parse(time.RFC3339, view.NextUpdate)
	if err != nil || !next.After(time.Now()) {
		t.Fatal("next update", view.NextUpdate, err)
	}
	saved := *view.Config.Schedule
	// 画面へ渡すコピーから、キャッシュの予定を変更できない。
	view.Config.Schedule.Time = "23:59"
	current, _ := repo.networkView()
	if current.Config.Schedule.Time != "04:00" {
		t.Fatal("cache schedule was mutable")
	}
	// 旧APIは予定を省略しても保持し、明示nullだけが間隔方式へ切り替える。
	get, _ = client.request("GET", "/api/v1/networks", "", nil)
	legacy := current.Config
	legacy.Schedule = nil
	raw, _ = json.Marshal(legacy)
	response, body = client.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"legacy-schedule-preserve"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	current, _ = repo.networkView()
	if current.Config.Schedule == nil || *current.Config.Schedule != saved {
		t.Fatal("legacy API reset schedule", current)
	}
	if err := repo.refreshNetworks(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	current, _ = repo.networkView()
	if requests.Load() != 1 || current.Config.Schedule == nil || *current.Config.Schedule != saved || !reflect.DeepEqual(current.Config.Overrides, config.Overrides) {
		t.Fatal("manual refresh changed schedule", current)
	}
	state := repo.site.State()
	var site siteState
	if strictjson.Decode(state.Rows["site:state"].Value, &site) != nil || site.MinimumReader != networkScheduleReader {
		t.Fatal("reader boundary", site)
	}
	state.Rows = maps.Clone(state.Rows)
	site.MinimumReader = networkScheduleReader - 1
	row := state.Rows["site:state"]
	row.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = row
	if _, err := inspectSiteState(state, site.ID, cfg.Public.BaseURL); err == nil {
		t.Fatal("old reader accepted schedule")
	}
	client.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	current, err = repo.networkView()
	if err != nil || current.Config.Schedule == nil || *current.Config.Schedule != saved || !reflect.DeepEqual(current.Config.Overrides, config.Overrides) {
		t.Fatal("schedule not durable", current, err)
	}
	client = newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login after recovery")
	}
	get, _ = client.request("GET", "/api/v1/networks", "", nil)
	legacy = current.Config
	legacy.Enabled, legacy.Schedule = false, nil
	raw, _ = json.Marshal(legacy)
	raw = append([]byte(`{"schedule":null,`), raw[1:]...)
	response, body = client.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"schedule-clear-0001"}})
	current, err = repo.networkView()
	if response.StatusCode != 200 || err != nil || current.Config.Schedule != nil || current.Config.Enabled || !reflect.DeepEqual(current.Config.Overrides, config.Overrides) {
		t.Fatal("explicit null did not clear schedule", response.StatusCode, body, current, err)
	}
}

// TestNetworkScheduleJSON は旧設定を読み、未知・重複・不完全な新予定を拒否する。
func TestNetworkScheduleJSON(t *testing.T) {
	config := defaultNetworkConfig()
	raw, _ := json.Marshal(config)
	var decoded NetworkConfig
	if strings.Contains(string(raw), `"schedule"`) || strictjson.Decode(raw, &decoded) != nil || decoded.Schedule != nil {
		t.Fatal("legacy config changed", string(raw))
	}
	for _, schedule := range []string{`{"frequency":"daily","time":"04:00"}`, `{"frequency":"daily","time":"04:00","weekday":0,"day":1,"starts_at_ns":"0","extra":true}`, `{"frequency":"daily","time":"04:00","time":"05:00","weekday":0,"day":1,"starts_at_ns":"0"}`} {
		body := append([]byte(`{"schedule":`+schedule+`,`), raw[1:]...)
		if strictjson.Decode(body, &decoded) == nil {
			t.Fatal("invalid schedule accepted", schedule)
		}
	}
}

// TestNetworkScheduleResume は停止中の古い予定を再開時に即時実行せず、次回から有効にする。
func TestNetworkScheduleResume(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	now := time.Now().In(domain.JST)
	repo.mu.Lock()
	state, err := loadNetworkState(repo.site.State())
	if err == nil {
		state.Version++
		state.Config.Sources = defaultNetworkSources()[:1]
		state.Config.Schedule = &NetworkSchedule{Frequency: "daily", Time: now.Format("15:04"), StartsAt: domain.Time(now.AddDate(0, 0, -1).UnixNano())}
		err = repo.publishNetworks(state, nil, "network_config", nil)
	}
	repo.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	get, _ := client.request("GET", "/api/v1/networks", "", nil)
	state.Config.Enabled = true
	raw, _ := json.Marshal(state.Config)
	response, body := client.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"schedule-resume-0001"}})
	view, err := repo.networkView()
	if response.StatusCode != 200 || err != nil || view.Attempt != 0 || view.Config.Schedule.StartsAt <= state.Config.Schedule.StartsAt {
		t.Fatal("resume did not activate schedule", response.StatusCode, body, view, err)
	}
	next, err := time.Parse(time.RFC3339, view.NextUpdate)
	if err != nil || !next.After(time.Now()) {
		t.Fatal("resume used paused slot", view.NextUpdate, err)
	}
}
