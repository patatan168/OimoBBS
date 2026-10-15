// キャップの期限・担当板・許可・保存失敗・旧資格の並行停止を検査する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCapAuthenticationBoundaries(t *testing.T) {
	id, board := domain.NewID(), domain.NewID()
	key := domain.Hash{99}
	secret := strings.Repeat("A", 43)
	value := capValue{ID: id, Name: "運営", Secret: capSecret(key, id, secret), KeyID: 9, Boards: []domain.ID{board}, Permissions: []string{"create", "post"}, Enabled: true, Expires: 2000, Revision: 1, Created: 1000}
	reg := &capRegistry{Records: map[domain.ID]capValue{id: value}}
	for _, tt := range []struct {
		at domain.Time
		ok bool
	}{{999, false}, {1000, true}, {1999, true}, {2000, false}} {
		_, e := authenticateCap(reg, key, id, secret, board, true, tt.at)
		if (e == nil) != tt.ok {
			t.Fatal("expiry", tt, e)
		}
	}
	for _, tt := range []struct {
		key       domain.Hash
		id, board domain.ID
		secret    string
	}{{domain.Hash{98}, id, board, secret}, {key, domain.NewID(), board, secret}, {key, id, domain.NewID(), secret}, {key, id, board, strings.Repeat("B", 43)}} {
		if _, e := authenticateCap(reg, tt.key, tt.id, tt.secret, tt.board, true, 1100); e == nil {
			t.Fatal("authentication bypass")
		}
	}
	value.Permissions = []string{"create"}
	reg.Records[id] = value
	if _, e := authenticateCap(reg, key, id, secret, board, false, 1100); e == nil {
		t.Fatal("reply permission bypass")
	}
	revoked := domain.Time(1500)
	value.Revoked = &revoked
	value.Enabled = false
	value.Revision = 2
	reg.Records[id] = value
	if _, e := authenticateCap(reg, key, id, secret, board, true, 1100); e == nil {
		t.Fatal("revoked credential restored")
	}
	raw, _ := json.Marshal(value)
	if snapshotSiteValue("cap", id.String(), nil, raw) != nil || validateSiteValue("cap", id.String(), nil, raw) == nil || validateSiteValue("cap", id.String(), raw, json.RawMessage("null")) == nil {
		t.Fatal("snapshot/mutation/deletion boundary")
	}
}
func TestCapStateFixture(t *testing.T) {
	raw, e := os.ReadFile(filepath.Join("..", "..", "docs", "design", "fixtures", "caps.json"))
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Schema int `json:"schema"`
		Reader int `json:"reader"`
		Secret int `json:"secret_bytes"`
		Cases  []struct {
			Name        string   `json:"name"`
			Display     string   `json:"display"`
			Days        int      `json:"days"`
			Boards      int      `json:"boards"`
			Permissions []string `json:"permissions"`
			Valid       bool     `json:"valid"`
		} `json:"cases"`
	}
	if e = json.Unmarshal(raw, &f); e != nil || f.Schema != 1 || f.Reader != 35 || f.Secret != 32 {
		t.Fatal("fixture", e)
	}
	for _, tt := range f.Cases {
		t.Run(tt.Name, func(t *testing.T) {
			boards := []domain.ID{}
			for range tt.Boards {
				boards = append(boards, domain.NewID())
			}
			sortCapBoards(boards)
			v := capValue{ID: domain.NewID(), Name: tt.Display, Secret: domain.Hash{1}, KeyID: 9, Boards: boards, Permissions: tt.Permissions, Enabled: true, Expires: 1 + domain.Time(tt.Days)*86400e9, Revision: 1, Created: 1}
			if (validateCapState(v) == nil) != tt.Valid {
				t.Fatal("fixture mismatch")
			}
		})
	}
}
func sortCapBoards(v []domain.ID) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j].String() < v[j-1].String(); j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}

func TestCapOnlyPostingAndRequiredCookie(t *testing.T) {
	cfg, r, board := anonymousAdminFixture(t, "required")
	defer func() { r.Close() }()
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	list, _ := c.request("GET", "/api/v1/caps", "", nil)
	issuanceServer, issue, _ := anonymousHTTP(t, r, siteID(r.site.State()))
	issue("POST", "/test/bbs.cgi", url.Values{"bbs": {"news"}, "subject": {"発行確認"}, "MESSAGE": {"本文"}, "oimo_request_id": {"cap-cas-cookie-issue01"}})
	issuanceServer.Close()
	createdResponse, cap, secret, createBody := c.capChange("/api/v1/caps", capInput{"運営", []domain.ID{board}, []string{"create", "post"}, domain.Time(time.Now().Add(time.Hour).UnixNano())}, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if createdResponse.StatusCode != 200 || secret == "" {
		t.Fatal("cookie issuance conflicted with cap revision", createBody)
	}
	res, v := c.board(board.String())
	edit := v.Settings
	edit.Create, edit.Reply = "cap_only", "cap_only"
	edit.Anonymous = &AdminAnonymousSettings{Mode: "required"}
	raw, _ := json.Marshal(edit)
	h := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}}
	res, body := c.request("PATCH", "/api/v1/boards/"+board.String()+"/settings", string(raw), h)
	if res.StatusCode != 200 {
		t.Fatal("cap_only", res.StatusCode, body)
	}
	server, request, cookies := anonymousHTTP(t, r, siteID(r.site.State()))
	defer server.Close()
	fields := url.Values{"bbs": {"news"}, "subject": {"キャップ専用"}, "MESSAGE": {"本文"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "oimo_request_id": {"required-cookie-cap-001"}}
	request("POST", "/test/bbs.cgi", fields)
	token := cookies["oimo_anon"]
	if token == nil {
		t.Fatal("token issuance")
	}
	delete(cookies, "oimo_anon")
	res, body = request("POST", "/test/bbs.cgi", fields)
	rows, _ := r.rateHistory()
	if !strings.Contains(body, "2ch_X:cookie") || len(rows) != 0 {
		t.Fatal("cap bypassed cookie", res.StatusCode, body)
	}
	cookies["oimo_anon"] = token
	res, body = request("POST", "/test/bbs.cgi", fields)
	if strings.Contains(body, "ERROR:") || strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("cap/cookie acceptance", res.StatusCode, body)
	}
	rows, _ = r.rateHistory()
	if len(rows) != 1 || len(rows[0].record.Keys) != 4 || rows[0].record.Schema != postcapture.Schema {
		t.Fatal("ordinary limits not charged", rows)
	}
	// 正規のCookie・確認を持つ匿名主体でもcap_onlyを迂回しない。
	fields.Del("mail")
	fields.Set("subject", "匿名")
	fields.Set("oimo_request_id", "required-cookie-anon-001")
	request("POST", "/test/bbs.cgi", fields)
	res, body = request("POST", "/test/bbs.cgi", fields)
	rows, _ = r.rateHistory()
	decoded, e := textcodec.Decode([]byte(body))
	if e != nil || len(rows) != 1 || !strings.Contains(decoded, "キャップ") {
		t.Fatal("anonymous cap_only bypass", res.StatusCode, body)
	}
	c.server.Close()
	server.Close()
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("cap/token recovery", e)
	}
}

func TestCapFailedSaveStopsWriters(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	b, e := r.CreateBoard(context.Background(), "failcap", "保存試験")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	list, _ := c.request("GET", "/api/v1/caps", "", nil)
	r.site.Close()
	res, _, secret, body := c.capChange("/api/v1/caps", capInput{"保存失敗", []domain.ID{b.ID}, []string{"post"}, domain.Time(time.Now().Add(time.Hour).UnixNano())}, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 503 || secret != "" || !strings.Contains(body, "SAVE_UNCERTAIN") || res.Header.Get("X-Operation-ID") == "" {
		t.Fatal("failure", res.StatusCode, body)
	}
	r.mu.Lock()
	stopped := r.stopped
	r.mu.Unlock()
	if !stopped || len(r.liveCaps.Load().Records) != 0 {
		t.Fatal("uncertain credential published")
	}
}

func TestCapRevokeConcurrentCommit(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	board, e := r.CreateBoard(context.Background(), "concap", "並行試験")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	cap, secret := createTestCap(t, r, c, board.ID, []string{"create", "post"})
	form := formServer(t, r, siteID(r.site.State()), board.ID)
	defer form.Close()
	fields := url.Values{"bbs": {"concap"}, "subject": {"並行"}, "MESSAGE": {"本文"}, "mail": {"#cap:" + cap.ID.String() + ":" + secret}, "oimo_request_id": {"concurrent-cap-post-001"}}
	pending, e := sendFormOnce(form, fields, "")
	if e != nil || pending.Confirmation == nil {
		t.Fatal(e)
	}
	detail, _ := c.request("GET", "/api/v1/caps/"+cap.ID.String(), "", nil)
	b := r.posting[board.ID]
	original := b.clock
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	if _, e = b.worker.Submit(context.Background(), func() (any, error) {
		b.clock = func() time.Time { once.Do(func() { close(entered); <-release }); return original() }
		return nil, nil
	}); e != nil {
		t.Fatal(e)
	}
	done := make(chan formResult, 1)
	go func() {
		res, e := sendFormOnce(form, fields, pending.Confirmation.Token)
		if e != nil {
			t.Error(e)
		}
		done <- res
	}()
	<-entered
	revoked := make(chan int, 1)
	go func() {
		res, _, _, _ := c.capChange("/api/v1/caps/"+cap.ID.String()+"/revoke", struct{}{}, detail.Header.Get("ETag"), detail.Header.Get("X-CSRF-Token"), domain.NewID().String())
		revoked <- res.StatusCode
	}()
	close(release)
	accepted := <-done
	if !accepted.Accepted || <-revoked != 200 {
		t.Fatal("concurrent boundary")
	}
	if _, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = original; return nil, nil }); e != nil {
		t.Fatal(e)
	}
	fields.Del("subject")
	fields.Set("key", fmt.Sprint(accepted.Key))
	fields.Set("MESSAGE", "停止後")
	fields.Set("oimo_request_id", "concurrent-cap-after01")
	if result, e := sendForm(form, fields); e != nil || result.Accepted || result.Confirmation != nil {
		t.Fatal("post-revoke accepted", result, e)
	}
	form.Close()
	c.server.Close()
	r.Close()
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("durable boundary", e)
	}
}

func TestCapAdministratorScope(t *testing.T) {
	_, r := adminFixture(t)
	defer r.Close()
	board, e := r.CreateBoard(context.Background(), "scope", "担当")
	if e != nil {
		t.Fatal(e)
	}
	other, e := r.CreateBoard(context.Background(), "outside", "担当外")
	if e != nil {
		t.Fatal(e)
	}
	owner := newAdminClient(t, r)
	defer owner.server.Close()
	if owner.login(adminTestSecret) != 303 || owner.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	outside, _ := createTestCap(t, r, owner, other.ID, []string{"post"})
	list, _ := owner.request("GET", "/api/v1/administrators", "", nil)
	input := accountInput{Login: "cap.manager", Display: "板管理者", Password: "cap-manager-private-password", Access: AdministratorAccess{Role: "board_admin", Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true}}
	res, _, body := owner.accountChange("POST", "/api/v1/administrators", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("account", res.StatusCode, body)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	_, loginPage := c.request("GET", "/login", "", nil)
	csrf := pageFields(loginPage).Get("csrf")
	res, _ = c.request("POST", "/login", url.Values{"login": {"cap.manager"}, "password": {input.Password}, "csrf": {csrf}}.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 || c.reauth(input.Password) != 200 {
		t.Fatal("limited login", res.StatusCode)
	}
	created, _ := createTestCap(t, r, c, board.ID, []string{"post"})
	res, body = c.request("GET", "/api/v1/caps", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, created.ID.String()) || strings.Contains(body, outside.ID.String()) {
		t.Fatal("scope list", res.StatusCode, body)
	}
	visibleETag := res.Header.Get("ETag")
	if visibleETag != capListETag(1) {
		t.Fatal("outside cap count disclosed", visibleETag)
	}
	createTestCap(t, r, owner, other.ID, []string{"post"})
	afterOutside, _ := c.request("GET", "/api/v1/caps", "", nil)
	if afterOutside.Header.Get("ETag") != visibleETag {
		t.Fatal("outside change disclosed")
	}
	response, _, secret, _ := c.capChange("/api/v1/caps", capInput{"担当追加", []domain.ID{board.ID}, []string{"post"}, domain.Time(time.Now().Add(time.Hour).UnixNano())}, visibleETag, afterOutside.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if response.StatusCode != 200 || secret == "" {
		t.Fatal("outside change invalidated scoped CAS", response.StatusCode)
	}
	assertCapUpdateScope(t, r, c, created, outside, other.ID)
	if res, _ = c.request("GET", "/api/v1/caps/"+outside.ID.String(), "", nil); res.StatusCode != 404 {
		t.Fatal("scope detail disclosure")
	}
	current, _ := c.request("GET", "/api/v1/caps", "", nil)
	res, _, _, _ = c.capChange("/api/v1/caps", capInput{"担当外", []domain.ID{other.ID}, []string{"post"}, domain.Time(time.Now().Add(time.Hour).UnixNano())}, current.Header.Get("ETag"), current.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 403 {
		t.Fatal("scope grant", res.StatusCode)
	}
}
