// 資格変更の原子的な再発行、固定再送、旧投稿復旧と管理境界を実HTTPで検査する。
package bootstrap

import (
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

type capUpdateFixture struct {
	cfg           Config
	r             *Repository
	client        *adminClient
	first, second BoardInfo
	cap           AdminCap
	secret        string
}

// newCapUpdateFixture は二板と再認証済み管理者、変更前の資格を作る。
func newCapUpdateFixture(t *testing.T) capUpdateFixture {
	t.Helper()
	cfg, r := adminFixture(t)
	t.Cleanup(func() { _ = r.Close() })
	first, e := r.CreateBoard(t.Context(), "capfirst", "変更前")
	if e != nil {
		t.Fatal(e)
	}
	second, e := r.CreateBoard(t.Context(), "capsecond", "変更後")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	t.Cleanup(c.server.Close)
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("authentication")
	}
	cap, secret := createTestCap(t, r, c, first.ID, []string{"create", "post"})
	return capUpdateFixture{cfg, r, c, first, second, cap, secret}
}

func TestCapUpdateLifecycle(t *testing.T) {
	f := newCapUpdateFixture(t)
	original := assertCapUpdatePost(t, f.r, f.first, f.cap, f.secret, 0, "cap-update-original", true)
	path := "/api/v1/caps/" + f.cap.ID.String()
	get, _ := f.client.request("GET", path, "", nil)
	input := capInput{"更新した運営", []domain.ID{f.second.ID}, []string{"create"}, 0}
	response, changed, secret, body := f.client.capChange(path+"/update", input, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Update-Token"), "cap-update-fixed-request")
	if response.StatusCode != 200 || secret == "" || changed.ID == f.cap.ID || changed.Expires != 0 {
		t.Fatal(response.StatusCode, body)
	}
	assertCapUpdateReplay(t, f, path, input, get, changed, secret)
	assertCapUpdateAudit(t, f, changed, secret)
	assertCapUpdatePost(t, f.r, f.first, f.cap, f.secret, 0, "cap-update-old-blocked", false)
	created := assertCapUpdatePost(t, f.r, f.second, changed, secret, 0, "cap-update-new-created", true)
	assertCapUpdatePost(t, f.r, f.second, changed, secret, created, "cap-update-new-reply-denied", false)
	if e := f.r.Close(); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(f.cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("old proof recovery after update", e)
	}
	defer reopened.Close()
	if snapshot, e := reopened.Thread(t.Context(), f.first.ID, original); e != nil || snapshot == nil {
		t.Fatal("old accepted content lost", e)
	}
	assertCapUpdatePost(t, reopened, f.second, changed, secret, 0, "cap-update-after-restart", true)
	assertCapUpdateSecretsAbsent(t, f.cfg.DataDir, f.secret, secret)
}

// assertCapUpdateReplay は異なる更新の衝突と秘密を含まない同一再送を確認する。
func assertCapUpdateReplay(t *testing.T, f capUpdateFixture, path string, input capInput, get *http.Response, changed AdminCap, secret string) {
	t.Helper()
	response, repeated, extra, body := f.client.capChange(path+"/update", input, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Update-Token"), "cap-update-fixed-request")
	if response.StatusCode != 200 || repeated.ID != changed.ID || extra != "" || strings.Contains(body, secret) {
		t.Fatal("update replay", response.StatusCode, body)
	}
	input.Permissions = []string{"post"}
	response, _, _, _ = f.client.capChange(path+"/update", input, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Update-Token"), "cap-update-fixed-request")
	if response.StatusCode != 409 {
		t.Fatal("request conflict", response.StatusCode)
	}
	reg := f.r.liveCaps.Load()
	if reg.Records[f.cap.ID].Enabled || !reg.Records[changed.ID].Enabled {
		t.Fatal("replacement not atomic")
	}
}

// assertCapUpdatePost は変更前後の資格を通常投稿経路で検査する。
func assertCapUpdatePost(t *testing.T, r *Repository, board BoardInfo, cap AdminCap, secret string, key uint64, request string, accepted bool) uint64 {
	t.Helper()
	server := formServer(t, r, siteID(r.site.State()), board.ID)
	defer server.Close()
	fields := url.Values{"bbs": {board.Key}, "MESSAGE": {"資格変更の投稿"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "oimo_request_id": {request}}
	if key == 0 {
		fields.Set("subject", "キャップ変更")
	} else {
		fields.Set("key", fmt.Sprint(key))
	}
	result, e := sendForm(server, fields)
	if e != nil || result.Accepted != accepted {
		t.Fatal("post authorization", result, e)
	}
	return result.Key
}

func TestCapUpdateInvalidIsNonMutating(t *testing.T) {
	f := newCapUpdateFixture(t)
	path := "/api/v1/caps/" + f.cap.ID.String()
	get, _ := f.client.request("GET", path, "", nil)
	before := f.r.site.State()
	input := capInput{"更新", []domain.ID{f.second.ID, f.second.ID}, []string{"post"}, 0}
	response, _, secret, _ := f.client.capChange(path+"/update", input, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Update-Token"), "cap-update-invalid-request")
	if response.StatusCode != 422 || secret != "" || !reflect.DeepEqual(before, f.r.site.State()) {
		t.Fatal("invalid update changed state", response.StatusCode)
	}
}

// assertCapUpdateScope は元の担当外と変更先の担当外を別々に拒否する。
func assertCapUpdateScope(t *testing.T, r *Repository, c *adminClient, visible, hidden AdminCap, outside domain.ID) {
	t.Helper()
	path := "/api/v1/caps/" + visible.ID.String()
	get, _ := c.request("GET", path, "", nil)
	before := r.site.State()
	input := capInput{"担当変更", []domain.ID{outside}, []string{"post"}, 0}
	response, _, _, _ := c.capChange(path+"/update", input, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Update-Token"), "cap-update-outside-scope")
	if response.StatusCode != 403 || !reflect.DeepEqual(before, r.site.State()) {
		t.Fatal("new scope bypass", response.StatusCode)
	}
	session, e := r.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	hiddenPath := "/api/v1/caps/" + hidden.ID.String() + "/update"
	response, _, _, _ = c.capChange(hiddenPath, input, hidden.ETag(), session.CSRF(hiddenPath), "cap-update-hidden-scope")
	if response.StatusCode != 404 || !reflect.DeepEqual(before, r.site.State()) {
		t.Fatal("hidden source scope bypass", response.StatusCode)
	}
}

func TestCapUpdateHTML(t *testing.T) {
	f := newCapUpdateFixture(t)
	response, page := f.client.request("GET", "/caps", "", nil)
	path := "/caps/" + f.cap.ID.String() + "/update"
	start := strings.Index(page, `<form action="`+path+`"`)
	if response.StatusCode != 200 || start < 0 {
		t.Fatal("update form absent", response.StatusCode)
	}
	end := strings.Index(page[start:], "</form>")
	if end < 0 {
		t.Fatal("form incomplete")
	}
	fields := pageFields(page[start : start+end])
	fields.Set("display_name", "変更後の運営")
	fields.Set("board_ids", f.second.ID.String())
	fields.Set("permissions", "create")
	expiry := (capRow{AdminCap: f.cap}).ExpiryInput()
	if !strings.Contains(page[start:start+end], `value="`+expiry+`"`) {
		t.Fatal("expiry prefill absent")
	}
	fields.Set("expires_at", expiry)
	response, body := f.client.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 || !strings.Contains(body, "#cap:") {
		t.Fatal("HTML update", response.StatusCode, body)
	}
	assertCapUpdateHTMLResult(t, f)
	response, body = f.client.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 200 || strings.Contains(body, "#cap:") {
		t.Fatal("HTML secret replay", response.StatusCode)
	}
}

// assertCapUpdateHTMLResult は日時入力の精度とフォーム選択を保存結果へ照合する。
func assertCapUpdateHTMLResult(t *testing.T, f capUpdateFixture) {
	t.Helper()
	reg := f.r.liveCaps.Load()
	if reg.Records[f.cap.ID].Enabled || len(reg.Records) != 2 {
		t.Fatal("HTML replacement")
	}
	for id, cap := range reg.Records {
		if id == f.cap.ID {
			continue
		}
		if cap.Expires != f.cap.Expires || cap.Name != "変更後の運営" || !reflect.DeepEqual(cap.Boards, []domain.ID{f.second.ID}) || !reflect.DeepEqual(cap.Permissions, []string{"create"}) {
			t.Fatal("HTML updated fields differ")
		}
	}
}

func TestCapUpdateFailedSave(t *testing.T) {
	f := newCapUpdateFixture(t)
	path := "/api/v1/caps/" + f.cap.ID.String()
	get, _ := f.client.request("GET", path, "", nil)
	_ = f.r.site.Close()
	input := capInput{"保存失敗", []domain.ID{f.second.ID}, []string{"create"}, 0}
	response, _, secret, body := f.client.capChange(path+"/update", input, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Update-Token"), "cap-update-save-failed")
	if response.StatusCode != 503 || secret != "" || !strings.Contains(body, "SAVE_UNCERTAIN") {
		t.Fatal("uncertain update response", response.StatusCode)
	}
	f.r.mu.Lock()
	stopped := f.r.stopped
	f.r.mu.Unlock()
	reg := f.r.liveCaps.Load()
	if !stopped || len(reg.Records) != 1 || !reg.Records[f.cap.ID].Enabled {
		t.Fatal("uncertain update published")
	}
}

// assertCapUpdateSecretsAbsent は資格変更前後の原秘密が保存fileへ残らないことを確認する。
func assertCapUpdateSecretsAbsent(t *testing.T, root string, secrets ...string) {
	t.Helper()
	for _, data := range requiredStartupFiles(t, root) {
		for _, secret := range secrets {
			if strings.Contains(string(data), secret) {
				t.Fatal("cap secret persisted")
			}
		}
	}
}

// assertCapUpdateAudit は固定再送でも一件の変更として新旧IDだけを記録することを検査する。
func assertCapUpdateAudit(t *testing.T, f capUpdateFixture, changed AdminCap, secret string) {
	t.Helper()
	response, page, body := f.client.audit("action=cap_update")
	if response.StatusCode != 200 || len(page.Entries) != 1 {
		t.Fatal("update audit", response.StatusCode, len(page.Entries))
	}
	targets := page.Entries[0].Targets
	if len(targets) != 2 || !strings.Contains(strings.Join(targets, " "), f.cap.ID.String()) || !strings.Contains(strings.Join(targets, " "), changed.ID.String()) {
		t.Fatal("audit targets")
	}
	for _, value := range []string{f.secret, secret, changed.Name} {
		if strings.Contains(body, value) {
			t.Fatal("audit private value exposed")
		}
	}
	response, html := f.client.request("GET", "/audit?action=cap_update", "", nil)
	if response.StatusCode != 200 || !strings.Contains(html, "キャップ条件を変更して再発行") {
		t.Fatal("audit action label", response.StatusCode)
	}
}
