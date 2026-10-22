// 公開資料のID設定を管理HTML・SETTING.TXT・投稿DAT・再起動で照合する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
)

// 手書きの期待値はBBS_SLIP/SETTING.TXTの公開資料（2026-10-04照合）に基づく。
func Test5chBoardIdentityConformance(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	b, e := r.CreateBoard(context.Background(), "identity", "ID仕様")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	observer, e := evidence.NewHTTPObserver(siteID(r.site.State()), domain.NewID(), "identity-conformance")
	if e != nil {
		t.Fatal(e)
	}
	public := httptest.NewUnstartedServer(r.SiteWebHandler(observer))
	public.Config.ConnContext = observer.ConnContext
	public.Start()
	defer public.Close()
	form := formServer(t, r, siteID(r.site.State()), b.ID)
	defer form.Close()
	path := "/api/v1/boards/" + b.ID.String() + "/settings"
	histories := map[uint64]string{}
	for _, tc := range []struct {
		mode, setting string
		id, question  bool
	}{
		{"required", "BBS_FORCE_ID=checked\n", true, false},
		{"optional", "", false, true},
		{"hidden", "BBS_NO_ID=checked\n", false, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			res, body := c.request("GET", path, "", nil)
			var data struct {
				Data AdminBoard `json:"data"`
			}
			if json.Unmarshal([]byte(body), &data) != nil {
				t.Fatal("settings")
			}
			edit := data.Data.Settings
			edit.Identity = &AdminIdentitySettings{IDMode: tc.mode, SlipMode: "none", AllowStrengthen: true, Networks: []identity.NetworkClass{}}
			raw, _ := json.Marshal(edit)
			res, body = c.request("PATCH", path, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"conformance-" + tc.mode}})
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode, body)
			}
			req, _ := http.NewRequest("GET", public.URL+"/identity/SETTING.TXT", nil)
			req.Host = "127.0.0.1:9080"
			feed, e := public.Client().Do(req)
			if e != nil {
				t.Fatal(e)
			}
			bytes, _ := io.ReadAll(feed.Body)
			feed.Body.Close()
			settings, e := textcodec.Decode(bytes)
			if e != nil || feed.StatusCode != 200 {
				t.Fatal("feed", e, feed.StatusCode)
			}
			for _, key := range []string{"BBS_FORCE_ID=", "BBS_NO_ID=", "BBS_FORCE_NOID="} {
				if strings.Contains(settings, key) != (tc.setting != "" && strings.HasPrefix(tc.setting, key)) {
					t.Fatal("wrong ID setting", settings)
				}
			}
			if tc.setting != "" && !strings.Contains(settings, tc.setting) {
				t.Fatal(settings)
			}
			_, page := c.request("GET", "/boards/"+b.ID.String()+"/settings", "", nil)
			if !strings.Contains(page, `value="`+tc.mode+`" selected`) || !strings.Contains(page, "ID末尾も非表示") {
				t.Fatal("UI mismatch")
			}
			fields := url.Values{"bbs": {"identity"}, "subject": {"題"}, "MESSAGE": {"本文"}, "mail": {"sage"}, "oimo_request_id": {"conformance-display-" + tc.mode}}
			result, e := sendForm(form, fields)
			if e != nil || !result.Accepted {
				t.Fatal(result, e)
			}
			snap, e := r.Thread(context.Background(), b.ID, result.Key)
			if e != nil {
				t.Fatal(e)
			}
			dat, e := textcodec.Decode(snap.DAT)
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(dat, "ID:") != (tc.id || tc.question) || strings.Contains(dat, "ID:???") != tc.question {
				t.Fatal(dat)
			}
			if tc.id {
				parts := strings.Split(dat, "<>")
				id := strings.Split(parts[2], " ID:")[1]
				if len(id) != 8 {
					t.Fatal("none suffix appended", id)
				}
			}
			histories[result.Key] = string(snap.DAT)
			command := url.Values{"bbs": {"identity"}, "key": {fmt.Sprint(result.Key)}, "FROM": {"!id:on"}, "MESSAGE": {"表示追加"}, "oimo_request_id": {"conformance-command-" + tc.mode}}
			result, e = sendForm(form, command)
			if e != nil {
				t.Fatal(e)
			}
			if !result.Accepted {
				t.Fatal("command override", tc.mode, result)
			}
			if result.Accepted {
				snap, e = r.Thread(context.Background(), b.ID, result.Key)
				if e != nil {
					t.Fatal(e)
				}
				dat, _ = textcodec.Decode(snap.DAT)
				lines := strings.Split(strings.TrimSuffix(dat, "\n"), "\n")
				if len(lines) != 2 || !strings.Contains(lines[1], "ID:") {
					t.Fatal(dat)
				}
				histories[result.Key] = string(snap.DAT)
			}
		})
	}
	var site siteState
	if strictjson.Decode(r.site.State().Rows["site:state"].Value, &site) != nil || site.MinimumReader != 70 {
		t.Fatal("identity reader gate", site.MinimumReader)
	}
	public.Close()
	form.Close()
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("restart", e)
	}
	for key, want := range histories {
		snap, e := r.Thread(context.Background(), b.ID, key)
		if e != nil || string(snap.DAT) != want {
			t.Fatal("history changed", key, e)
		}
	}
}

func Test5chIDFormSelection(t *testing.T) {
	for _, mode := range []string{"required", "optional", "hidden"} {
		v := url.Values{"id_selection": {"1"}, "id_mode": {mode}}
		if e := normalizeIDSelection(v); e != nil || v.Has("id_selection") || v.Get("require_id") != "false" {
			t.Fatal(v, e)
		}
	}
	for _, bad := range []url.Values{
		{"id_selection": {"1"}, "id_mode": {"optional"}, "require_id": {"true"}},
		{"id_selection": {"1", "1"}, "id_mode": {"optional"}},
		{"id_selection": {"1"}, "id_mode": {"invalid"}},
	} {
		if normalizeIDSelection(bad) == nil {
			t.Fatal("ambiguous ID accepted", bad)
		}
	}
	legacy := url.Values{"id_mode": {"optional"}, "require_id": {"true"}}
	if normalizeIDSelection(legacy) != nil || legacy.Get("require_id") != "true" {
		t.Fatal("legacy mutated")
	}
}

func Test5chIPSettingValue(t *testing.T) {
	board := boardValue{Name: "IP表示", Settings: defaultBoardSettings()}
	board.Settings.Identity.RequireIP = true
	raw, e := legacySettings(board)
	if e != nil {
		t.Fatal(e)
	}
	text, e := textcodec.Decode(raw)
	if e != nil || !strings.Contains(text, "BBS_DISP_IP=siberia\n") || strings.Contains(text, "BBS_DISP_IP=checked") {
		t.Fatal(text, e)
	}
}

// Test5chThreadIDSelection は旧必須bitのあるスレッドも単一選択で任意IDへ戻せることを確認する。
func Test5chThreadIDSelection(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	b, e := r.CreateBoard(context.Background(), "idform", "ID選択")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	form := formServer(t, r, siteID(r.site.State()), b.ID)
	defer form.Close()
	created, e := sendForm(form, url.Values{"bbs": {"idform"}, "subject": {"題"}, "MESSAGE": {"元レス"}, "oimo_request_id": {"id-choice-thread-create"}})
	if e != nil || !created.Accepted {
		t.Fatal(created, e)
	}
	api := fmt.Sprintf("/api/v1/boards/%s/threads/%d/actions", b.ID, created.Key)
	res, body := c.request("GET", api, "", nil)
	var view struct {
		Data threadActionView `json:"data"`
	}
	if json.Unmarshal([]byte(body), &view) != nil {
		t.Fatal("view")
	}
	p := view.Data.Policy
	p.IDMode = "optional"
	p.RequireID = true
	raw, _ := json.Marshal(AdminThreadAction{Kind: "update_policy", Target: "", Policy: &p})
	res, body = c.request("POST", api, string(raw), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "If-Match": {res.Header.Get("ETag")}, "Idempotency-Key": {"id-choice-legacy-bit"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	path := strings.TrimPrefix(api, "/api/v1")
	res, body = c.request("GET", path, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `value="required" selected`) || strings.Contains(body, `<select name="require_id">`) {
		t.Fatal("effective ID selection")
	}
	f := pageFields(body)
	for k, v := range map[string]string{"step": "confirm", "kind": "update_policy", "target": "", "id_mode": "optional", "slip_mode": "none", "post_limit": "1000", "dat_limit": "524288"} {
		f.Set(k, v)
	}
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, body = c.request("POST", path, f.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "メール欄が空の投稿でIDを表示") {
		t.Fatal("confirm", res.StatusCode, body)
	}
	f = pageFields(body)
	res, body = c.request("POST", path, f.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "反映済み") {
		t.Fatal("apply", res.StatusCode, body)
	}
	_, body = c.request("GET", api, "", nil)
	if json.Unmarshal([]byte(body), &view) != nil || view.Data.Policy.IDMode != "optional" || view.Data.Policy.RequireID {
		t.Fatal("ID bit carried over")
	}
	reply, e := sendForm(form, url.Values{"bbs": {"idform"}, "key": {fmt.Sprint(created.Key)}, "mail": {"sage"}, "MESSAGE": {"次レス"}, "oimo_request_id": {"id-choice-optional-reply"}})
	if e != nil || !reply.Accepted {
		t.Fatal(reply, e)
	}
	snap, e := r.Thread(context.Background(), b.ID, created.Key)
	if e != nil {
		t.Fatal(e)
	}
	dat, e := textcodec.Decode(snap.DAT)
	lines := strings.Split(strings.TrimSuffix(dat, "\n"), "\n")
	if e != nil || len(lines) != 2 || !strings.Contains(lines[1], "ID:???<>") {
		t.Fatal(dat, e)
	}
}
