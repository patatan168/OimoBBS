// 実管理フォームで板チェック、無期限資格の交換/失効と復旧、再認証の戻り先を検査する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
	"time"
)

func TestBoardSelectionCapLifecycle(t *testing.T) {
	cfg, r := adminFixture(t)
	defer func() { r.Close() }()
	b, e := r.CreateBoard(t.Context(), "selection", "選択する板")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, _ := c.request("GET", "/caps", "", nil)
	if res.StatusCode != 303 || res.Header.Get("Location") != "/reauth?return_to=%2Fcaps" {
		t.Fatal("reauth route", res.StatusCode, res.Header.Get("Location"))
	}
	res, page := c.request("GET", res.Header.Get("Location"), "", nil)
	v := pageFields(page)
	v.Set("password", adminTestSecret)
	res, _ = c.request("POST", "/reauth?return_to=%2Fcaps", v.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 || res.Header.Get("Location") != "/caps" {
		t.Fatal("return", res.StatusCode)
	}
	_, page = c.request("GET", "/caps", "", nil)
	if !strings.Contains(page, "選択する板（selection）") || strings.Contains(page, "担当板固定ID") {
		t.Fatal("board picker")
	}
	v = pageFields(page)
	v.Set("board_selection", "1")
	v.Set("board_ids", b.ID.String())
	v.Set("display_name", "運営")
	v["permissions"] = []string{"post", "create"}
	v.Set("expires_at", "")
	res, page = c.request("POST", "/caps", v.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 200 || !strings.Contains(page, "#cap:") {
		t.Fatal("issue", res.StatusCode)
	}
	_, body := c.request("GET", "/api/v1/caps", "", nil)
	var list struct {
		Data []AdminCap `json:"data"`
	}
	if json.Unmarshal([]byte(body), &list) != nil || len(list.Data) != 1 {
		t.Fatal("list")
	}
	cap := list.Data[0]
	if cap.Expires != 0 || cap.ExpiryLabel() != "期限なし" {
		t.Fatal("unlimited")
	}
	key, e := readCapKey(r)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	reg := r.liveCaps.Load()
	value := reg.Records[cap.ID]
	r.mu.Unlock()
	if !value.permits(b.ID, false, domain.Time(time.Now().Add(365*24*time.Hour).UnixNano())) {
		t.Fatal("unlimited auth")
	}
	get, _ := c.request("GET", "/api/v1/caps/"+cap.ID.String(), "", nil)
	res, replacement, secret, _ := c.capChange("/api/v1/caps/"+cap.ID.String()+"/reset", struct{}{}, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Reset-Token"), domain.NewID().String())
	if res.StatusCode != 200 || replacement.Expires != 0 || replacement.ID == cap.ID || secret == "" {
		t.Fatal("reset", res.StatusCode)
	}
	if r.liveCaps.Load().Records[cap.ID].Enabled {
		t.Fatal("old cap active")
	}
	if _, e = authenticateCap(r.liveCaps.Load(), key, replacement.ID, secret, b.ID, false, domain.Time(time.Now().UnixNano())); e != nil {
		t.Fatal("new cap", e)
	}
	get, _ = c.request("GET", "/api/v1/caps/"+replacement.ID.String(), "", nil)
	res, _, _, _ = c.capChange("/api/v1/caps/"+replacement.ID.String()+"/revoke", struct{}{}, get.Header.Get("ETag"), get.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("delete", res.StatusCode)
	}
	if _, e = authenticateCap(r.liveCaps.Load(), key, replacement.ID, secret, b.ID, false, domain.Time(time.Now().UnixNano())); e == nil {
		t.Fatal("deleted credential works")
	}
	c.server.Close()
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	r, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reopen", e)
	}
	if r.liveCaps.Load().Records[replacement.ID].Enabled || len(r.liveCaps.Load().Records) != 2 {
		t.Fatal("history")
	}
}

func TestBoardSelectionNormalizationAndAudit(t *testing.T) {
	a, b := domain.NewID(), domain.NewID()
	v := url.Values{"board_selection": {"1"}, "board_ids": {a.String(), b.String()}}
	if normalizeBoardSelection(v) != nil || len(strings.Fields(v.Get("board_ids"))) != 2 {
		t.Fatal("multi")
	}
	if normalizeBoardSelection(url.Values{"board_selection": {"1"}}) != nil {
		t.Fatal("empty selection")
	}
	if normalizeBoardSelection(url.Values{"board_selection": {"1"}, "board_ids": {a.String(), a.String()}}) == nil {
		t.Fatal("duplicates")
	}
	all := url.Values{}
	for range maxPersistentBoards {
		all.Add("board", domain.NewID().String())
	}
	if _, _, e := parseAuditQuery(all.Encode(), time.Now()); e != nil {
		t.Fatal("all boards query", e)
	}
	now := time.Now()
	q, _, e := parseAuditQuery(url.Values{"board": {a.String(), b.String()}}.Encode(), now)
	if e != nil || len(q.Boards) != 2 || !auditMatches(AuditEntry{Owner: b}, q) || auditMatches(AuditEntry{Owner: domain.NewID()}, q) {
		t.Fatal("audit multi", e)
	}
	for _, bad := range []string{"https://example.com", "//example.com", "/caps/../../login"} {
		if got := adminReturnPath(bad); got != "/" && got != "/caps" {
			t.Fatal("unsafe return")
		}
	}
	if capHTTPValue(AdminCap{Expires: 0}).ExpiresAt != "" {
		t.Fatal("API unlimited")
	}
	_, r := adminFixture(t)
	defer r.Close()
	binfo, e := r.CreateBoard(t.Context(), "selecttest", "担当チェック")
	if e != nil {
		t.Fatal(e)
	}
	c := newAdminClient(t, r)
	defer c.server.Close()
	c.login(adminTestSecret)
	c.reauth(adminTestSecret)
	res, page := c.request("GET", "/administrators", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, `type="checkbox" name="board_ids"`) {
		t.Fatal("accounts")
	}
	v = pageFields(page)
	v.Set("board_selection", "1")
	v.Set("board_ids", binfo.ID.String())
	v.Set("login_name", "selected.admin")
	v.Set("display_name", "選択管理者")
	v.Set("password", "private-board-selection-test")
	v.Set("role", "board_admin")
	v.Set("extra_permissions", "")
	v.Set("enabled", "true")
	res, _ = c.request("POST", "/administrators", v.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("account save", res.StatusCode)
	}
	_, body := c.request("GET", "/api/v1/administrators", "", nil)
	var accounts struct {
		Data []AdminAccount `json:"data"`
	}
	json.Unmarshal([]byte(body), &accounts)
	for _, account := range accounts.Data {
		if account.Login == "selected.admin" {
			_, page = c.request("GET", "/administrators/"+account.ID.String(), "", nil)
			if !strings.Contains(page, `value="`+binfo.ID.String()+`" checked`) {
				t.Fatal("selection lost")
			}
		}
	}
}
