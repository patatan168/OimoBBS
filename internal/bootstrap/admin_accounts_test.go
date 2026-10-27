// 実HTTPで再認証・秘密非公開・保存再送・世代失効・最後の管理者保護を確認する。
package bootstrap

import (
	"encoding/json"
	"net/http"

	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

// reauth は本番と同じCSRF付き再認証APIを通す。
func (c *adminClient) reauth(secret string) int {
	res, _ := c.request("GET", "/api/v1/reauth", "", nil)
	body, _ := json.Marshal(map[string]string{"password": secret})
	res, _ = c.request("POST", "/api/v1/reauth", string(body), http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}})
	return res.StatusCode
}
func (c *adminClient) accountChange(method, path string, input accountInput, etag, csrf, key string) (*http.Response, AdminAccount, string) {
	body, _ := json.Marshal(input)
	headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}, "Idempotency-Key": {key}}
	if etag != "" {
		headers.Set("If-Match", etag)
	}
	res, text := c.request(method, path, string(body), headers)
	var response struct {
		Data AdminAccount `json:"data"`
	}
	_ = json.Unmarshal([]byte(text), &response)
	return res, response.Data, text
}
func TestOnlineAdministratorLifecycle(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	if res, _ := c.request("GET", "/api/v1/administrators", "", nil); res.StatusCode != 403 {
		t.Fatal("missing reauth", res.StatusCode)
	}
	if c.reauth("incorrect private password") != 401 {
		t.Fatal("incorrect reauth")
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	list, _ := c.request("GET", "/api/v1/administrators", "", nil)
	if list.StatusCode != 200 {
		t.Fatal("list")
	}
	input := accountInput{Login: "viewer.one", Display: "<表示>", Password: "another-private-admin-password", Access: AdministratorAccess{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}}
	key := domain.NewID().String()
	res, created, body := c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), key)
	if res.StatusCode != 200 || created.Generation != 1 || strings.Contains(body, input.Password) {
		t.Fatal("create", res.StatusCode, body)
	}
	first := created
	res, replayed, _ := c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), key)
	if res.StatusCode != 200 || replayed.ID != first.ID || replayed.Revision != first.Revision {
		t.Fatal("repeat creates another account")
	}
	input.Display = "別入力"
	res, _, _ = c.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), key)
	if res.StatusCode != 409 {
		t.Fatal("different repeat", res.StatusCode)
	}
	path := "/api/v1/administrators/" + first.ID.String()
	detail, _ := c.request("GET", path, "", nil)
	input.Password = ""
	input.Access.Enabled = false
	res, updated, _ := c.accountChange("PATCH", path, input, detail.Header.Get("ETag"), detail.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 || updated.Generation != 2 || updated.Access.Enabled {
		t.Fatal("update", res.StatusCode)
	}
	res, _, _ = c.accountChange("PATCH", path, input, detail.Header.Get("ETag"), detail.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 412 {
		t.Fatal("stale revision", res.StatusCode)
	}
	// HTMLは保存秘密を再掲せず、表示名をエスケープする。
	if res, page := c.request("GET", "/administrators/"+first.ID.String(), "", nil); res.StatusCode != 200 || strings.Contains(page, "another-private-admin-password") || strings.Contains(page, "salt_base64") {
		t.Fatal("html secret", res.StatusCode)
	}
	_, rows := c.request("GET", "/api/v1/administrators", "", nil)
	var data struct {
		Data []AdminAccount `json:"data"`
	}
	if json.Unmarshal([]byte(rows), &data) != nil {
		t.Fatal(rows)
	}
	var owner AdminAccount
	for _, a := range data.Data {
		if a.Login == "owner" {
			owner = a
		}
	}
	ownerPath := "/api/v1/administrators/" + owner.ID.String()
	ownerDetail, _ := c.request("GET", ownerPath, "", nil)
	self := accountInput{Login: owner.Login, Display: owner.Display, Access: owner.Access}
	self.Access.Enabled = false
	res, _, _ = c.accountChange("PATCH", ownerPath, self, ownerDetail.Header.Get("ETag"), ownerDetail.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 409 {
		t.Fatal("last administrator disabled", res.StatusCode)
	}
	self.Access.Enabled = true
	self.Display = "所有者更新"
	res, _, _ = c.accountChange("PATCH", ownerPath, self, ownerDetail.Header.Get("ETag"), ownerDetail.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("self update", res.StatusCode)
	}
	if res, _ := c.request("GET", "/api/v1/site", "", nil); res.StatusCode != 401 {
		t.Fatal("old generation accepted", res.StatusCode)
	}
	c.server.Close()
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo = nil
	var e error
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("restart auth")
	}
	list, rows = c.request("GET", "/api/v1/administrators", "", nil)
	if list.StatusCode != 200 || !strings.Contains(rows, "所有者更新") {
		t.Fatal("restart settings", rows)
	}
	// 確定済みcreateの要求を再起動後に元のETagで照会できる。
	input.Display = "<表示>"
	input.Password = "another-private-admin-password"
	input.Access.Enabled = true
	res, replayed, _ = c.accountChange("POST", "/api/v1/administrators", input, accountListETag(first.Revision-1), list.Header.Get("X-CSRF-Token"), key)
	if res.StatusCode != 200 || replayed.ID != first.ID || replayed.Generation != 1 {
		t.Fatal("restart receipt", res.StatusCode)
	}
}
func TestReauthRequestValidation(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := c.request("GET", "/api/v1/reauth", "", nil)
	var state struct {
		Reauthenticated bool `json:"reauthenticated"`
		ValidForSeconds int  `json:"valid_for_seconds"`
	}
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &state) != nil || state.Reauthenticated || state.ValidForSeconds != 600 {
		t.Fatal("reauth GET duration", res.StatusCode, body)
	}
	csrf := res.Header.Get("X-CSRF-Token")
	for _, tc := range []struct {
		body, csrf string
		status     int
	}{{`{"password":"x"}`, "wrong", 403}, {`{"password":"x","role":"site_admin"}`, csrf, 400}, {`{"password":"x","password":"y"}`, csrf, 400}, {`{"password":""}`, csrf, 400}} {
		res, _ := c.request("POST", "/api/v1/reauth", tc.body, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {tc.csrf}})
		if res.StatusCode != tc.status {
			t.Fatal("request", res.StatusCode, tc.status)
		}
	}
	if res, page := c.request("GET", "/reauth", "", nil); res.StatusCode != 200 || !strings.Contains(page, "current-password") || !strings.Contains(page, "再認証は10分間有効です") {
		t.Fatal("reauth html")
	}
	res, body = c.request("POST", "/api/v1/reauth", `{"password":"`+adminTestSecret+`"}`, http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}})
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &state) != nil || !state.Reauthenticated || state.ValidForSeconds != 600 {
		t.Fatal("reauth POST duration", res.StatusCode, body)
	}
}

func TestAdministratorChangeRejectsAndUncertainSave(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	list, _ := c.request("GET", "/api/v1/administrators", "", nil)
	csrf, etag := list.Header.Get("X-CSRF-Token"), list.Header.Get("ETag")
	input := accountInput{Login: "second.admin", Display: "二人目", Password: "second-administrator-secret", Access: AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}}
	for _, tc := range []struct {
		etag, csrf string
		status     int
	}{{"", csrf, 428}, {etag, "wrong", 403}, {`"administrators-0"`, csrf, 412}} {
		res, _, _ := c.accountChange("POST", "/api/v1/administrators", input, tc.etag, tc.csrf, domain.NewID().String())
		if res.StatusCode != tc.status {
			t.Fatal("reject", res.StatusCode, tc.status)
		}
	}
	input.Password = "short"
	if res, _, _ := c.accountChange("POST", "/api/v1/administrators", input, etag, csrf, domain.NewID().String()); res.StatusCode != 422 {
		t.Fatal("short password", res.StatusCode)
	}
	input.Password = "second-administrator-secret"
	input.Access.Permissions = []string{"arbitrary.permission"}
	if res, _, _ := c.accountChange("POST", "/api/v1/administrators", input, etag, csrf, domain.NewID().String()); res.StatusCode != 422 {
		t.Fatal("invented permission", res.StatusCode)
	}
	input.Access.Permissions = []string{}
	current, _ := c.request("GET", "/api/v1/administrators", "", nil)
	if current.Header.Get("ETag") != etag {
		t.Fatal("rejected request modified state")
	}
	// 既存frameを閉じてappendを拒否させる。成功receiptを返さずRepository全体を停止する。
	if e := repo.site.Close(); e != nil {
		t.Fatal(e)
	}
	res, _, body := c.accountChange("POST", "/api/v1/administrators", input, etag, csrf, domain.NewID().String())
	if res.StatusCode != 503 || res.Header.Get("X-Operation-ID") == "" || !strings.Contains(body, "SAVE_UNCERTAIN") {
		t.Fatal("uncertain append", res.StatusCode, body)
	}
	repo.mu.Lock()
	stopped := repo.stopped
	repo.mu.Unlock()
	if !stopped {
		t.Fatal("writes still available")
	}
}

func TestAdministratorReceiptReaderAndValidation(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	res, _ := c.request("GET", "/api/v1/administrators", "", nil)
	input := accountInput{Login: "receipt.user", Display: "記録", Password: "private-receipt-password", Access: AdministratorAccess{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}}
	if changed, _, _ := c.accountChange("POST", "/api/v1/administrators", input, res.Header.Get("ETag"), res.Header.Get("X-CSRF-Token"), domain.NewID().String()); changed.StatusCode != 200 {
		t.Fatal(changed.StatusCode)
	}
	state := repo.site.State()
	for key, row := range state.Rows {
		if !strings.HasPrefix(key, "admin_receipt:") || !isAccountReceipt(row.Value) {
			continue
		}
		var v accountReceipt
		if json.Unmarshal(row.Value, &v) != nil {
			t.Fatal("decode")
		}
		if validateAdminReceipt(strings.TrimPrefix(key, "admin_receipt:"), nil, row.Value) != nil {
			t.Fatal("valid receipt rejected")
		}
		v.Account.Access.Permissions = []string{"evidence.manage", "evidence.manage"}
		bad, _ := json.Marshal(v)
		if validateAdminReceipt(strings.TrimPrefix(key, "admin_receipt:"), nil, bad) == nil {
			t.Fatal("duplicate permissions receipt")
		}
		for _, access := range []AdministratorAccess{
			{Role: "reporter", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true},
			{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{"private_posts.read"}, Enabled: true},
			{Role: "moderator", Boards: []domain.ID{}, Permissions: []string{"evidence.hold"}, Enabled: true},
		} {
			invalid := v
			invalid.Account.Access = access
			bad, _ := json.Marshal(invalid)
			if validateAdminReceipt(strings.TrimPrefix(key, "admin_receipt:"), nil, bad) == nil {
				t.Fatal("removed or unusable access in persisted receipt", access)
			}
		}
		v.Account.Access.Permissions = []string{}
		v.Expires--
		bad, _ = json.Marshal(v)
		if validateAdminReceipt(strings.TrimPrefix(key, "admin_receipt:"), nil, bad) == nil {
			t.Fatal("bad receipt lifetime")
		}
	}
	row := state.Rows["site:state"]
	var site siteState
	if json.Unmarshal(row.Value, &site) != nil {
		t.Fatal("site")
	}
	site.MinimumReader = 16
	row.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = row
	if _, e := inspectSiteState(state, site.ID, repo.cfg.Public.BaseURL); e == nil {
		t.Fatal("reader16 accepted account receipt")
	}
}

// TestAdministratorHTMLFailurePreservesRequest は結果不明でも非秘密入力と要求IDを保持する。
func TestAdministratorHTMLFailurePreservesRequest(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("auth")
	}
	_, page := c.request("GET", "/administrators", "", nil)
	fields := pageFields(page)
	for k, v := range map[string]string{"login_name": "form.user", "display_name": "<非秘密>", "password": "private-html-admin-secret", "role": "moderator", "board_ids": "", "extra_permissions": "", "enabled": "true"} {
		fields.Set(k, v)
	}
	if e := repo.site.Close(); e != nil {
		t.Fatal(e)
	}
	res, body := c.request("POST", "/administrators", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	saved := pageFields(body)
	if res.StatusCode != 503 || res.Header.Get("X-Operation-ID") == "" || saved.Get("request_id") != fields.Get("request_id") || !strings.Contains(body, `value="form.user"`) || !strings.Contains(body, `value="&lt;非秘密&gt;"`) || strings.Contains(body, "private-html-admin-secret") || saved.Get("password") != "" {
		t.Fatal("failure form", res.StatusCode, body)
	}
}
