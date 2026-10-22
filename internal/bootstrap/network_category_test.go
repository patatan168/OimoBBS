// カテゴリーの完全型・旧形式拒否・入力境界を検証する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"testing"
)

func TestNetworkCategoryCompleteFormat(t *testing.T) {
	legacy := `{"id":"docomo","name":"docomo","kind":"mobile","label":"ｽﾌﾟｯｯ","suffix":"d"}`
	var category NetworkCategory
	if e := strictjson.Decode([]byte(legacy), &category); e == nil {
		t.Fatal("old category accepted")
	}
	complete := strings.TrimSuffix(legacy, "}") + `,"description":"","provider":"docomo"}`
	if e := strictjson.Decode([]byte(complete), &category); e != nil {
		t.Fatal(e)
	}
	raw, e := json.Marshal(category)
	if e != nil || !strings.Contains(string(raw), `"provider":"docomo"`) || !strings.Contains(string(raw), `"description":""`) {
		t.Fatal(string(raw), e)
	}
	for _, raw := range []string{
		strings.Replace(legacy, `"name":"docomo",`, "", 1),
		strings.Replace(legacy, `"name":"docomo"`, `"name":"docomo","extra":true`, 1),
		strings.Replace(legacy, `"name":"docomo"`, `"name":"docomo","description":null`, 1),
		strings.Replace(legacy, `"name":"docomo"`, `"name":"docomo","description":12`, 1),
		strings.Replace(legacy, `"name":"docomo"`, `"name":"docomo","description":"a","description":"b"`, 1),
	} {
		if strictjson.Decode([]byte(raw), &category) == nil {
			t.Fatal("invalid category accepted", raw)
		}
	}
	for _, value := range []string{"", "ドコモの携帯回線。\r\n管理用の説明\tメモ", strings.Repeat("あ", 1024)} {
		if !validNetworkDescription(value) {
			t.Fatal("valid description rejected")
		}
	}
	for _, value := range []string{strings.Repeat("あ", 1025), "\x00", "\x1b", string([]byte{255})} {
		if validNetworkDescription(value) {
			t.Fatal("invalid description accepted")
		}
	}
}

// TestNetworkCategoryRepository は完全形式のカテゴリーを保存し再起動で照合する。
func TestNetworkCategoryRepository(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	r.mu.Lock()
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		r.mu.Unlock()
		t.Fatal(e)
	}
	site.MinimumReader = 30
	config := defaultNetworkConfig()
	config.Categories = config.Categories[:21]
	for i := range config.Categories {
		config.Categories[i].Description = ""
	}
	legacy := networkState{Version: 1, Config: config, Rows: []identity.NetworkClass{}}
	appendErr := appendControl(r.site, "network_config", []store.Mutation{mutation("site", "state", site, nil), mutation("network", "active", legacy, nil)}, []string{})
	r.mu.Unlock()
	if appendErr != nil {
		t.Fatal(appendErr)
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	view, e := r.networkView()
	if e != nil || len(view.Config.Categories) != 21 || view.Config.Categories[1].Description != "" {
		t.Fatal(view, e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	get, _ := c.request("GET", "/api/v1/networks", "", nil)
	view.Config.Categories[1].Description = "ｽﾌﾟｯｯ はドコモの携帯回線を表します。"
	raw, _ := json.Marshal(view.Config)
	response, body := c.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-legacy-description"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader != 70 {
		t.Fatal(site, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	view, e = r.networkView()
	if e != nil || view.Config.Categories[1].Description != "ｽﾌﾟｯｯ はドコモの携帯回線を表します。" {
		t.Fatal(view, e)
	}
}
