// 意味で選ぶ管理フォームの保存・旧形式互換・不正な選択の拒否を検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/identity"
	"strings"
	"testing"
	"time"
)

func TestMeaningfulBoardForm(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(context.Background(), "meaning", "表示設定")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := "/boards/" + board.ID.String() + "/settings"
	get, page := c.request("GET", path, "", nil)
	if get.StatusCode != 200 || !strings.Contains(page, ">回線名と週ごとの識別子を表示（ワッチョイ）（!slip:vvvvv）</option>") || strings.Contains(page, ">vvvvv</option>") || strings.Contains(page, "<textarea name=\"network_classes\"") {
		t.Fatal("meaningful controls missing")
	}
	hidden := pageFields(page)
	_, body := c.request("GET", "/api/v1"+path, "", nil)
	var data struct {
		Data AdminBoard `json:"data"`
	}
	if json.Unmarshal([]byte(body), &data) != nil {
		t.Fatal("settings")
	}
	f := adminBoardFields(data.Data.Settings)
	f.Set("csrf", hidden.Get("csrf"))
	f.Set("revision", hidden.Get("revision"))
	f.Set("request_id", "meaning-board-save")
	f.Set("slip_mode", "vvvvv")
	f.Set("display_selection", "1")
	f.Del("require_public_ip")
	f.Del("network_classes")
	f.Set("network_rows", "1")
	f["network_cidr"] = []string{"192.0.2.129/24", ""}
	f["network_kind"] = []string{"mvno", "unknown"}
	f["network_label"] = []string{"", ""}
	f["network_suffix"] = []string{"", ""}
	res, body := c.request("POST", path, f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("save", res.StatusCode, body)
	}
	_, body = c.request("GET", "/api/v1"+path, "", nil)
	if json.Unmarshal([]byte(body), &data) != nil || data.Data.Settings.Identity.SlipMode != "vvvvv" || data.Data.Settings.Identity.RequireIP || len(data.Data.Settings.Identity.Networks) != 1 {
		t.Fatal("selection not saved")
	}
	row := data.Data.Settings.Identity.Networks[0]
	if row.CIDR != "192.0.2.0/24" || row.Kind != "mvno" || row.Label != "ﾌﾞｰｲﾓ" || row.Suffix != "M" {
		t.Fatal(row)
	}
	_, page = c.request("GET", path, "", nil)
	if !strings.Contains(page, `value="vvvvv" selected>回線名と週ごとの識別子`) || !strings.Contains(page, `name="network_cidr" value="192.0.2.0/24"`) {
		t.Fatal("saved labels missing")
	}
}

func TestPermissionCheckboxNormalization(t *testing.T) {
	for _, name := range []string{"extra_permissions", "permissions"} {
		values := []string{"evidence.manage"}
		if name == "permissions" {
			values = []string{"post", "create"}
		}
		v := url.Values{"permission_selection": {"1"}, name: values}
		if err := normalizePermissionSelection(v, name); err != nil || v.Has("permission_selection") || len(v[name]) != 1 {
			t.Fatal(v, err)
		}
		empty := url.Values{"permission_selection": {"1"}}
		if err := normalizePermissionSelection(empty, name); err != nil || empty.Get(name) != "" || len(empty[name]) != 1 {
			t.Fatal(empty, err)
		}
		for _, bad := range [][]string{{"invalid"}, {values[0], values[0]}} {
			if normalizePermissionSelection(url.Values{"permission_selection": {"1"}, name: bad}, name) == nil {
				t.Fatal("bad permission accepted")
			}
		}
		old := url.Values{name: {"legacy text"}}
		if err := normalizePermissionSelection(old, name); err != nil || old.Get(name) != "legacy text" {
			t.Fatal("legacy changed")
		}
	}
}

func TestRuleNetworkSelectionNormalization(t *testing.T) {
	v := url.Values{"field": {"line"}, "target": {""}, "line_target": {"mobile"}, "extra_field": {"body"}, "extra_value": {"本文"}, "line_extra": {"wifi"}}
	if err := normalizeRuleNetworkChoices(v); err != nil || v.Get("target") != "mobile" || v.Get("extra_value") != "本文" || v.Has("line_target") {
		t.Fatal(v, err)
	}
	v = url.Values{"field": {"body"}, "target": {"本文"}, "line_target": {"mobile"}, "extra_field": {"line"}, "extra_value": {""}, "line_extra": {"wifi"}}
	if err := normalizeRuleNetworkChoices(v); err != nil || v.Get("extra_value") != "wifi" || v.Get("target") != "本文" {
		t.Fatal(v, err)
	}
	bad := url.Values{"field": {"line", "body"}, "target": {""}, "line_target": {"mobile"}}
	if normalizeRuleNetworkChoices(bad) == nil {
		t.Fatal("duplicate field accepted")
	}
	bad = url.Values{"field": {"line"}, "target": {""}, "line_target": {"bad"}}
	if normalizeRuleNetworkChoices(bad) == nil {
		t.Fatal("unknown line accepted")
	}
}

func TestNetworkRowsErrorRetainsInput(t *testing.T) {
	v := url.Values{"network_rows": {"1"}, "network_cidr": {"not-an-ip"}, "network_kind": {"wifi"}, "network_label": {"表示名"}, "network_suffix": {"W"}}
	if err := normalizeBoardNetworkRows(v); err != nil {
		t.Fatal(err)
	}
	rows := adminBoardsPage{Values: v}.NetworkRows()
	if rows[0].CIDR != "not-an-ip" || rows[0].Label != "表示名" || identity.ValidateNetworks(rows[:1]) == nil {
		t.Fatal(rows)
	}
	v = url.Values{"network_rows": {"1"}, "network_cidr": {"1.1.1.1"}, "network_kind": {"wifi"}, "network_label": {""}}
	if normalizeBoardNetworkRows(v) == nil {
		t.Fatal("missing field accepted")
	}
}

func TestPermissionFormWithoutJavaScript(t *testing.T) {
	form := url.Values{"permission_selection": {"1"}, "extra_permissions": {"evidence.manage", "private_reports.read"}}
	req := httptest.NewRequest("POST", "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fields, err := adminForm(httptest.NewRecorder(), req, 1<<10, "extra_permissions")
	if err != nil || fields.Get("extra_permissions") != "evidence.manage private_reports.read" {
		t.Fatal(fields, err)
	}
}

func TestCapDatePickerJapaneseTime(t *testing.T) {
	date, err := parseCapExpiryForm("2026-10-05T12:30")
	if err != nil || date.UTC().Format(time.RFC3339) != "2026-10-05T03:30:00Z" {
		t.Fatal(date, err)
	}
	old, err := parseCapExpiryForm("2026-10-05T03:30:00Z")
	if err != nil || !old.Equal(date) {
		t.Fatal(old, err)
	}
	if _, err = parseCapExpiryForm("invalid"); err == nil {
		t.Fatal("invalid date accepted")
	}
}

func TestMeaningfulPermissionAndRuleForms(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, err := r.CreateBoard(context.Background(), "choices", "選択欄")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	header := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	_, page := c.request("GET", "/administrators", "", nil)
	if !strings.Contains(page, ">投稿・スレッドの管理担当</option>") || !strings.Contains(page, "記録の閲覧・保全・出力") || strings.Contains(page, "<textarea name=\"extra_permissions\"") {
		t.Fatal("role/permission labels missing")
	}
	fields := pageFields(page)
	fields.Set("login_name", "choice.viewer")
	fields.Set("display_name", "閲覧担当")
	fields.Set("password", "private-choice-viewer-password")
	fields.Set("role", "moderator")
	fields.Set("enabled", "true")
	fields.Set("board_ids", board.ID.String())
	fields["extra_permissions"] = []string{"evidence.manage", "private_reports.read"}
	res, _ := c.request("POST", "/administrators", fields.Encode(), header)
	if res.StatusCode != 303 {
		t.Fatal("account save", res.StatusCode)
	}
	var found administrator
	for _, row := range r.site.State().Rows {
		var value administrator
		if json.Unmarshal(row.Value, &value) == nil && value.Login == "choice.viewer" {
			found = value
		}
	}
	if found.Role != "moderator" || len(found.Permissions) != 2 {
		t.Fatal("account selections not saved")
	}
	_, page = c.request("GET", "/administrators/"+found.ID.String(), "", nil)
	if !strings.Contains(page, `value="evidence.manage" checked`) {
		t.Fatal("selected permission lost")
	}
	// 編集と一時パスワード発行のフォームは、別のCSRFを持つ。
	// ブラウザと同じく送信するフォームだけからhidden値を取得する。
	accountPath := "/administrators/" + found.ID.String()
	fields = postManagementFields(t, page, accountPath)
	resetFields := postManagementFields(t, page, accountPath+"/password-reset")
	api, _ := c.request("GET", "/api/v1"+accountPath, "", nil)
	if api.StatusCode != 200 || fields.Get("csrf") != api.Header.Get("X-CSRF-Token") || fields.Get("csrf") == resetFields.Get("csrf") {
		t.Fatal("account form CSRF scope")
	}
	fields.Set("login_name", "choice.viewer")
	fields.Set("display_name", "閲覧担当")
	fields.Set("password", "")
	fields.Set("role", "moderator")
	fields.Set("enabled", "true")
	fields.Set("board_ids", board.ID.String())
	fields.Del("extra_permissions")
	updateCSRF := fields.Get("csrf")
	fields.Set("csrf", resetFields.Get("csrf"))
	res, _ = c.request("POST", accountPath, fields.Encode(), header)
	if res.StatusCode != 403 {
		t.Fatal("password reset CSRF accepted for account update", res.StatusCode)
	}
	fields.Set("csrf", updateCSRF)
	res, _ = c.request("POST", accountPath, fields.Encode(), header)
	if res.StatusCode != 303 {
		t.Fatal("permission clear", res.StatusCode)
	}
	var cleared administrator
	if err := json.Unmarshal(r.site.State().Rows["administrator:"+found.ID.String()].Value, &cleared); err != nil || len(cleared.Permissions) != 0 {
		t.Fatal("cleared permissions not saved", cleared.Permissions, err)
	}
	_, page = c.request("GET", "/administrators/"+found.ID.String(), "", nil)
	if strings.Contains(page, `value="evidence.manage" checked`) || strings.Contains(page, `value="private_reports.read" checked`) {
		t.Fatal("empty selection did not clear")
	}

	_, page = c.request("GET", "/caps", "", nil)
	if !strings.Contains(page, "返信する") || !strings.Contains(page, `name="expires_at" type="text" data-date-format="local" data-date-kind="expiry"`) || strings.Contains(page, "post・create") {
		t.Fatal("cap controls missing")
	}
	fields = pageFields(page)
	fields.Set("display_name", "投稿担当")
	fields.Set("board_ids", board.ID.String())
	fields.Set("permissions", "post")
	fields.Set("expires_at", "")
	res, _ = c.request("POST", "/caps", fields.Encode(), header)
	if res.StatusCode != 200 {
		t.Fatal("cap save", res.StatusCode)
	}
	_, page = c.request("GET", "/caps", "", nil)
	if !strings.Contains(page, "投稿担当") || !strings.Contains(page, "返信する") {
		t.Fatal("saved cap labels missing")
	}

	path := "/boards/" + board.ID.String() + "/rules"
	_, page = c.request("GET", path, "", nil)
	if !strings.Contains(page, `name="line_target"`) || !strings.Contains(page, ">携帯回線とMVNO</option>") {
		t.Fatal("rule line selector missing")
	}
	fields = ruleCreateFields(t, page)
	for key, value := range map[string]string{"field": "line", "operator": "exact", "effect": "deny", "target": "", "line_target": "mobile", "extra_field": "body", "extra_operator": "contains", "extra_value": "spam", "line_extra": "wifi", "operation": "both", "duration_minutes": "60", "reason_code": "manual", "allow_rule_ids": "", "refill_seconds": "", "burst": "", "window_limit": ""} {
		fields.Set(key, value)
	}
	res, _ = c.request("POST", path, fields.Encode(), header)
	if res.StatusCode != 303 {
		t.Fatal("rule save", res.StatusCode)
	}
	_, page = c.request("GET", path, "", nil)
	if !strings.Contains(page, "回線種別") || !strings.Contains(page, "携帯回線とMVNO") || !strings.Contains(page, "本文（部分一致） spam") {
		t.Fatal("saved rule meaning missing")
	}
}

func TestDisplaySelectionNormalization(t *testing.T) {
	for _, thread := range []bool{false, true} {
		v := url.Values{"display_selection": {"1"}, "slip_mode": {"vvvvv"}}
		if err := normalizeDisplaySelection(v, thread); err != nil || v.Get("require_public_ip") != "false" || v.Has("display_selection") {
			t.Fatal(v, err)
		}
		if thread && v.Get("require_slip_hash") != "false" {
			t.Fatal(v)
		}
	}
	for _, v := range []url.Values{
		{"display_selection": {"1"}, "slip_mode": {"vvvvv"}, "require_public_ip": {"true"}},
		{"display_selection": {"1", "1"}, "slip_mode": {"vvvvv"}},
		{"display_selection": {"1"}, "slip_mode": {"bad"}},
	} {
		if normalizeDisplaySelection(v, false) == nil {
			t.Fatal("ambiguous selection accepted", v)
		}
	}
	legacy := url.Values{"slip_mode": {"vvvvv"}, "require_public_ip": {"true"}}
	if normalizeDisplaySelection(legacy, false) != nil || legacy.Get("require_public_ip") != "true" {
		t.Fatal("legacy altered")
	}
}
