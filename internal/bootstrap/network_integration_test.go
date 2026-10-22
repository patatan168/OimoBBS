// 管理フォーム・自動取得・上書き・投稿表示とsnapshot切替後の復旧を実HTTPで検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// waitNetworkAttempt はバックグラウンド取得の完了を待つ。実時間依存を取得完了の確認に限定する。
func waitNetworkAttempt(t *testing.T, r *Repository, previous domain.Time) networkView {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		v, e := r.networkView()
		if e != nil {
			t.Fatal(e)
		}
		if v.Attempt > previous && !v.Running {
			return v
		}
		select {
		case <-deadline:
			t.Fatal("network update did not finish")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestNetworkManagementIntegration(t *testing.T) {
	cfg, r := adminFixture(t)
	useHealthyPostingCapacity(t, r)
	defer func() { r.Close() }()
	b, e := r.CreateBoard(context.Background(), "news", "共通分類")
	if e != nil {
		t.Fatal(e)
	}
	var bad atomic.Bool
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if bad.Load() {
			_, _ = w.Write([]byte(`{"invalid":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"asn":9605,"metadata":{"description":"fixture"},"prefixes":{"ipv4":["127.0.0.1/32"],"ipv6":["2001:db8::/32"]}}`))
	}))
	defer feed.Close()
	r.mu.Lock()
	r.networkClient = networkTestClient(feed)
	r.mu.Unlock()
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := c.request("GET", "/networks", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "無料の標準データで更新を開始") || !strings.Contains(body, "IPで判定を確認") || !strings.Contains(body, "上書きを追加") {
		t.Fatal(res.StatusCode, body)
	}
	api := "/api/v1/networks"
	get, _ := c.request("GET", api, "", nil)
	config := NetworkConfig{Categories: defaultNetworkCategories(), IntervalHours: 24, Sources: []NetworkSource{{Name: "試験取得元", Type: "asn", ASN: 9605, Kind: "mvno", Label: "ﾌﾞｰｲﾓ", Suffix: "M"}}, Overrides: []identity.NetworkClass{}}
	raw, _ := json.Marshal(config)
	headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-setup-request"}}
	res, body = c.request("PATCH", api, string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	res, body = c.request("PATCH", api, string(raw), headers)
	if res.StatusCode != 200 || !strings.Contains(body, `"duplicate":true`) {
		t.Fatal("retry", res.StatusCode, body)
	}
	get, _ = c.request("GET", api, "", nil)
	refreshHeaders := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}}
	res, body = c.request("POST", api+"/refresh", "{}", refreshHeaders)
	if res.StatusCode != 202 {
		t.Fatal(res.StatusCode, body)
	}
	fetched := waitNetworkAttempt(t, r, 0)
	if fetched.Count != 2 || fetched.Error != "" {
		t.Fatal(fetched)
	}
	// 共通分類が専ブラの投稿表示にも使われる。
	settingsPath := "/api/v1/boards/" + b.ID.String() + "/settings"
	get, body = c.request("GET", settingsPath, "", nil)
	var envelope struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil {
		t.Fatal(body)
	}
	edit := envelope.Data.Settings
	edit.Identity = &AdminIdentitySettings{IDMode: "required", SlipMode: "vvvvv", Networks: []identity.NetworkClass{}}
	raw, _ = json.Marshal(edit)
	res, body = c.request("PATCH", settingsPath, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-board-display"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	if e := r.EnableSlip(); e != nil {
		t.Fatal(e)
	}
	form := formServer(t, r, siteID(r.site.State()), b.ID, true)
	defer func() { form.Close() }()
	first, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"分類"}, "MESSAGE": {"元のレス"}, "oimo_request_id": {"network-first-create"}})
	if e != nil || !first.Accepted {
		t.Fatal(first, e)
	}
	snap, e := r.Thread(context.Background(), b.ID, first.Key)
	if e != nil || snap == nil {
		t.Fatal(e)
	}
	dat, e := textcodec.Decode(snap.DAT)
	if e != nil || !strings.Contains(dat, "(ﾌﾞｰｲﾓ ") || !strings.Contains(dat, "M<>") {
		t.Fatal(dat, e)
	}
	// JSONを編集せず、通常フォームから単一IPの共通上書きを登録する。
	_, body = c.request("GET", "/networks", "", nil)
	common := pageFields(body)
	fields := url.Values{"action": {"override_save"}, "csrf": {common.Get("csrf")}, "revision": {common.Get("revision")}, "request_id": {"network-ui-override-01"}, "index": {"-1"}, "cidr": {"127.0.0.1"}, "display_preset": {"custom"}, "kind": {"fixed"}, "label": {""}, "suffix": {""}}
	res, body = c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || !strings.Contains(body, "127.0.0.1/32") {
		t.Fatal(res.StatusCode, body)
	}
	probe, e := r.probeNetwork("::ffff:127.0.0.1")
	if e != nil || probe.Class.Kind != "fixed" || probe.Origin != "管理者の共通上書き" {
		t.Fatal(probe, e)
	}
	reply, e := sendForm(form, url.Values{"bbs": {"news"}, "key": {fmt.Sprint(first.Key)}, "MESSAGE": {"修正後"}, "oimo_request_id": {"network-new-reply-01"}})
	if e != nil || !reply.Accepted {
		t.Fatal(reply, e)
	}
	snap, e = r.Thread(context.Background(), b.ID, first.Key)
	if e != nil {
		t.Fatal(e)
	}
	dat, e = textcodec.Decode(snap.DAT)
	lines := strings.Split(strings.TrimSuffix(dat, "\n"), "\n")
	if e != nil || len(lines) != 2 || !strings.Contains(lines[0], "ﾌﾞｰｲﾓ") || !strings.Contains(lines[1], "(ﾜｯﾁｮｲ ") || !strings.Contains(lines[1], "0<>") {
		t.Fatal(dat, e)
	}
	// 更新失敗でも、前回の成功表と運営上書きを消さない。
	bad.Store(true)
	r.wakeNetworkUpdater(true)
	failed := waitNetworkAttempt(t, r, fetched.Attempt)
	if failed.Error != "invalid_data" || failed.Count != 2 || failed.LastSuccess != fetched.LastSuccess {
		t.Fatal(failed)
	}
	probe, _ = r.probeNetwork("127.0.0.1")
	if probe.Class.Kind != "fixed" {
		t.Fatal(probe)
	}
	// 満了receipt掃除・snapshot切替でも共通分類と上書きを復旧する。
	for range 2 {
		if _, e = r.EnableControlSnapshots(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	candidate := filepath.Join(candidateParent(t), "network-common")
	if _, e = r.PrepareControlSnapshot(context.Background(), candidate, 6); e != nil {
		t.Fatal(e)
	}
	form.Close()
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = ActivateControlSnapshot(context.Background(), cfg, candidate, postcapture.Validate); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reopen", e)
	}
	probe, e = r.probeNetwork("127.0.0.1")
	if e != nil || probe.Class.Kind != "fixed" {
		t.Fatal(probe, e)
	}
	probe, e = r.probeNetwork("2001:db8::1")
	if e != nil || probe.Class.Kind != "mvno" {
		t.Fatal(probe, e)
	}
}

func TestNetworkDiscardOldFetchAndFailedSave(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	started, release := make(chan struct{}), make(chan struct{})
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		close(started)
		<-release
		_, _ = w.Write([]byte("cidr,kind,label,suffix,provider\n192.0.2.0/24,mobile,携帯,S,docomo\n"))
	}))
	defer feed.Close()
	r.mu.Lock()
	r.networkClient = networkTestClient(feed)
	r.mu.Unlock()
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	config := defaultNetworkConfig()
	config.Sources = []NetworkSource{{Name: "test", Type: "csv", URL: "https://feed.example.invalid/list.csv"}}
	_, viewBody := c.request("GET", "/api/v1/networks", "", nil)
	_ = viewBody
	// 管理sessionはHTTPの認証済み集合から取得する。
	get, _ := c.request("GET", "/api/v1/networks", "", nil)
	raw, _ := json.Marshal(config)
	res, body := c.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-concurrent-01"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	done := make(chan error, 1)
	go func() { done <- r.refreshNetworks(context.Background(), true) }()
	<-started
	config.Sources = []NetworkSource{}
	get, _ = c.request("GET", "/api/v1/networks", "", nil)
	raw, _ = json.Marshal(config)
	res, body = c.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-concurrent-02"}})
	close(release)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	v, e := r.networkView()
	if e != nil || v.Count != 0 || len(v.Config.Sources) != 0 {
		t.Fatal("stale fetch published", v, e)
	}
	get, _ = c.request("GET", "/api/v1/networks", "", nil)
	config.Overrides = []identity.NetworkClass{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "固定", Suffix: "0"}}
	raw, _ = json.Marshal(config)
	r.site.Close()
	res, body = c.request("PATCH", "/api/v1/networks", string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {get.Header.Get("X-CSRF-Token")}, "If-Match": {get.Header.Get("ETag")}, "Idempotency-Key": {"network-failed-save-01"}})
	if res.StatusCode != 503 || !strings.Contains(body, "SAVE_UNCERTAIN") {
		t.Fatal(res.StatusCode, body)
	}
	probe, _ := r.probeNetwork("192.0.2.1")
	if probe.Class.Kind != "unknown" {
		t.Fatal("uncertain override published", probe)
	}
}

// TestNetworkCustomCategory は追加した表示カテゴリーを実フォームで選び、保存・再起動後の判定まで確認する。
func TestNetworkCustomCategory(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	submit := func(values url.Values) string {
		t.Helper()
		_, body := c.request("GET", "/networks", "", nil)
		hidden := pageFields(body)
		values.Set("csrf", hidden.Get("csrf"))
		values.Set("revision", hidden.Get("revision"))
		values.Set("request_id", domain.NewID().String())
		response, body := c.request("POST", "/networks", values.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if response.StatusCode != 200 {
			t.Fatal(response.StatusCode, body)
		}
		return body
	}
	body := submit(url.Values{"action": {"category_save"}, "index": {"-1"}, "category_id": {"future-mvno"}, "name": {"追加MVNO"}, "description": {"追加MVNOの回線です。"}, "kind": {"mvno"}, "label": {"ﾂｲｶﾓﾊﾞｲﾙ"}, "suffix": {"M"}})
	if !strings.Contains(body, "ﾂｲｶﾓﾊﾞｲﾙ（追加MVNO・ID末尾 M）") {
		t.Fatal("custom category absent from assignment menu")
	}
	categoryIndex := strconv.Itoa(len(defaultNetworkCategories()))
	editedDescription := "元の意味：追加MVNO。\n管理用メモ <script>確認</script>"
	body = submit(url.Values{"action": {"category_save"}, "index": {categoryIndex}, "category_id": {"future-mvno"}, "name": {"追加MVNO"}, "description": {editedDescription}, "kind": {"mvno"}, "label": {"ﾂｲｶﾓﾊﾞｲﾙ"}, "suffix": {"M"}})
	if !strings.Contains(body, "管理用メモ &lt;script&gt;確認&lt;/script&gt;") || strings.Contains(body, "<script>確認</script>") {
		t.Fatal("description missing or unescaped")
	}
	submit(url.Values{"action": {"override_save"}, "index": {"-1"}, "cidr": {"192.0.2.7"}, "display_preset": {"future-mvno"}, "kind": {"fixed"}, "label": {""}, "suffix": {""}})
	probe, e := r.probeNetwork("192.0.2.7")
	if e != nil || probe.Class.Kind != "mvno" || probe.Class.Label != "ﾂｲｶﾓﾊﾞｲﾙ" || probe.Class.Suffix != "M" {
		t.Fatal(probe, e)
	}
	// 同ID重複やカテゴリー不在は保存せず、元表を維持する。
	v, e := r.networkView()
	if e != nil {
		t.Fatal(e)
	}
	_, e = networkFormConfig(v.Config, url.Values{"action": {"category_save"}, "index": {"-1"}, "category_id": {"future-mvno"}, "name": {"重複"}, "description": {""}, "kind": {"fixed"}, "label": {"ﾜｯﾁｮｲ"}, "suffix": {"0"}})
	if e == nil {
		t.Fatal("duplicate category accepted")
	}
	_, e = networkFormConfig(v.Config, url.Values{"action": {"override_save"}, "index": {"-1"}, "cidr": {"192.0.2.8"}, "display_preset": {"missing"}, "kind": {"fixed"}, "label": {""}, "suffix": {""}})
	if e == nil {
		t.Fatal("missing category accepted")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	probe, e = r.probeNetwork("192.0.2.7")
	if e != nil || probe.Class.Label != "ﾂｲｶﾓﾊﾞｲﾙ" {
		t.Fatal(probe, e)
	}
	v, e = r.networkView()
	if e != nil || v.Config.Categories[len(v.Config.Categories)-1].ID != "future-mvno" || v.Config.Categories[len(v.Config.Categories)-1].Description != editedDescription {
		t.Fatal(v, e)
	}
	// 削除は一覧と選択肢から外し、保存済みの回線割り当てを維持する。
	c.server.Close()
	c = newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login after reopen")
	}
	body = submit(url.Values{"action": {"category_delete"}, "index": {categoryIndex}})
	if strings.Contains(body, `value="future-mvno"`) || strings.Contains(body, editedDescription) || !strings.Contains(body, "カテゴリーを削除しました") {
		t.Fatal("deleted category remained selectable")
	}
	body = submit(url.Values{"action": {"category_delete"}, "index": {"1"}})
	if strings.Contains(body, `<option value="docomo" >ｽﾌﾟｯｯ`) {
		t.Fatal("deleted builtin remained in category menu")
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	v, e = r.networkView()
	if e != nil || len(v.Config.Categories) != len(defaultNetworkCategories())-1 {
		t.Fatal(v, e)
	}
	probe, e = r.probeNetwork("192.0.2.7")
	if e != nil || probe.Class.Label != "ﾂｲｶﾓﾊﾞｲﾙ" {
		t.Fatal("deletion changed assigned classification", probe, e)
	}
	for _, category := range v.Config.Categories {
		if category.ID == "future-mvno" || category.ID == "docomo" {
			t.Fatal("deletion did not survive restart")
		}
	}

}

func TestNetworkProviderPresetDefaults(t *testing.T) {
	for _, p := range networkSourcePresets {
		s, e := networkSourceForm(url.Values{"preset": {p.ID}})
		if e != nil || s.Kind != p.Kind || s.ASN != p.ASN || s.Label != p.Label || s.Suffix != p.Suffix {
			t.Fatal(p, s, e)
		}
	}
	for _, p := range defaultNetworkCategories() {
		if validateNetworkCategories([]NetworkCategory{p}) != nil {
			t.Fatal(p)
		}
	}
}

// TestNetworkAutomaticUpdate は有効化時の非同期取得、間隔内の取得抑制、停止中Openを確認する。
func TestNetworkAutomaticUpdate(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	var calls atomic.Int32
	feed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"asn":9605,"prefixes":{"ipv4":["192.0.2.0/24"],"ipv6":[]}}`))
	}))
	defer feed.Close()
	r.mu.Lock()
	r.networkClient = networkTestClient(feed)
	r.mu.Unlock()
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, body := c.request("GET", "/networks", "", nil)
	hidden := pageFields(body)
	fields := url.Values{"action": {"source_save"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"network-auto-source"}, "index": {"-1"}, "preset": {"docomo"}, "display_preset": {"custom"}, "name": {""}, "asn": {""}, "url": {""}, "kind": {""}, "label": {""}, "suffix": {""}}
	res, body := c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	hidden = pageFields(body)
	fields = url.Values{"action": {"settings"}, "csrf": {hidden.Get("csrf")}, "revision": {hidden.Get("revision")}, "request_id": {"network-auto-enable"}, "enabled": {"true"}, "interval_hours": {"1"}}
	res, body = c.request("POST", "/networks", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	fetched := waitNetworkAttempt(t, r, 0)
	if fetched.Count != 1 || calls.Load() != 1 {
		t.Fatal(fetched, calls.Load())
	}
	if e := r.refreshNetworks(context.Background(), false); e != nil || calls.Load() != 1 {
		t.Fatal(e, calls.Load())
	}
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	r, e = OpenRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if r.networkDone != nil {
		t.Fatal("offline repository launched updater")
	}
	probe, e := r.probeNetwork("192.0.2.1")
	if e != nil || probe.Class.Label != "ｽﾌﾟｯｯ" {
		t.Fatal(probe, e)
	}
}
