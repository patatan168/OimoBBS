// 閲覧条件の保存・CSRF・競合・再送・再起動・管理画面の締め出し防止を実HTTPで検査する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/evidence"
	"os"
	"strconv"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func readingGet(t *testing.T, c *adminClient, route string) (AdminReading, http.Header) {
	t.Helper()
	res, body := c.request("GET", route, "", nil)
	if res.StatusCode != 200 {
		t.Fatal(route, res.StatusCode, body)
	}
	var view struct {
		Data AdminReading `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &view); err != nil {
		t.Fatal(err)
	}
	return view.Data, res.Header
}
func readingSave(t *testing.T, c *adminClient, route string, p ReadingPolicy, headers http.Header) (*http.Response, string) {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return c.request("POST", route, string(raw), headers)
}
func readingHeaders(h http.Header) http.Header {
	return http.Header{"Content-Type": {"application/json"}, "If-Match": {h.Get("ETag")}, "X-CSRF-Token": {h.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}}
}

func TestReadingHTTPPersistenceAndBoardFiltering(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "restricted", "制限対象板")
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.CreateBoard(t.Context(), "openboard", "公開板")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	route := "/api/v1/boards/" + board.ID.String() + "/reading"
	view, headers := readingGet(t, c, route)
	if view.Policy.Enabled || view.Revision != 0 {
		t.Fatal("default")
	}
	p := view.Policy
	p.Enabled = true
	p.DeniedCIDRs = []string{"192.0.2.0/24"}
	saveHeaders := readingHeaders(headers)
	bad := saveHeaders.Clone()
	bad.Set("X-CSRF-Token", "bad")
	if res, _ := readingSave(t, c, route, p, bad); res.StatusCode != 403 {
		t.Fatal("CSRF", res.StatusCode)
	}
	res, body := readingSave(t, c, route, p, saveHeaders)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	if res, body = readingSave(t, c, route, p, saveHeaders); res.StatusCode != 200 {
		t.Fatal("replay", res.StatusCode, body)
	}
	stale := saveHeaders.Clone()
	stale.Set("Idempotency-Key", domain.NewID().String())
	if res, _ := readingSave(t, c, route, p, stale); res.StatusCode != 412 {
		t.Fatal("CAS", res.StatusCode)
	}
	changed := p
	changed.DenyCrawlers = true
	if res, _ := readingSave(t, c, route, changed, saveHeaders); res.StatusCode != 409 {
		t.Fatal("request conflict", res.StatusCode)
	}
	res, body = c.request("GET", "/boards/"+board.ID.String()+"/reading", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `select name="enabled"`) || !strings.Contains(body, "192.0.2.0/24") {
		t.Fatal("HTML", res.StatusCode, body)
	}
	res, body = c.request("GET", "/boards/"+board.ID.String()+"/settings", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "/boards/"+board.ID.String()+"/reading") {
		t.Fatal("settings link", res.StatusCode)
	}
	request := func(method, path, ip string, header http.Header) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, cfg.Public.BaseURL+path, nil)
		req.RemoteAddr = ip + ":12345"
		req.Header = header.Clone()
		w := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(w, req)
		return w
	}
	for _, path := range []string{"/", "/bbsmenu.json", "/search"} {
		w := request("GET", path, "192.0.2.1", nil)
		if w.Code != 200 || strings.Contains(w.Body.String(), "restricted") || !strings.Contains(w.Body.String(), "openboard") {
			t.Fatal("filter", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
			t.Fatal("shared cache", w.Header())
		}
	}
	for _, method := range []string{"GET", "HEAD"} {
		for _, path := range []string{"/restricted/", "/restricted/index.html", "/restricted/subback.html", "/restricted/subject.txt", "/restricted/SETTING.TXT", "/restricted/head.txt", "/restricted/dat/123.dat", "/test/read.cgi/restricted/123/l50", "/web/post?bbs=restricted"} {
			w := request(method, path, "192.0.2.1", http.Header{"If-None-Match": {"*"}, "Range": {"bytes=0-5"}, "Accept-Encoding": {"gzip"}})
			if w.Code != 403 || w.Header().Get("ETag") != "" || method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("board deny", method, path, w.Code, w.Header())
			}
		}
	}
	if w := request("GET", "/restricted/subject.txt", "198.51.100.1", nil); w.Code != 200 {
		t.Fatal("allowed", w.Code, w.Body.String())
	}
	req := httptest.NewRequest("GET", cfg.Public.BaseURL+"/test/read.cgi/restricted/123/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	w := httptest.NewRecorder()
	repo.BoardWebHandler(board.ID, nil).ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("direct", w.Code)
	}
	common, headers := readingGet(t, c, "/api/v1/reading")
	common.Policy.Enabled = true
	common.Policy.DeniedCIDRs = []string{"198.51.100.0/24"}
	if res, body := readingSave(t, c, "/api/v1/reading", common.Policy, readingHeaders(headers)); res.StatusCode != 200 {
		t.Fatal("common", res.StatusCode, body)
	}
	if w := request("GET", "/openboard/subject.txt", "198.51.100.1", nil); w.Code != 403 {
		t.Fatal("common intersection", w.Code)
	}
	if res, _ := c.request("GET", "/login", "", nil); res.StatusCode != 200 {
		t.Fatal("common locked admin")
	}
	var site siteState
	if strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site) != nil || site.MinimumReader != 83 {
		t.Fatal("reader")
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	if err := repo.checkReading(board.ID.String(), netip.MustParseAddr("192.0.2.1"), ""); err == nil {
		t.Fatal("lost board restriction")
	}
	if err := repo.checkReading("site", netip.MustParseAddr("198.51.100.1"), ""); err == nil {
		t.Fatal("lost common restriction")
	}
}

func TestReadingAdminLockoutAndOfflineRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer func() { c.server.Close() }()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	view, headers := readingGet(t, c, "/api/v1/admin-access")
	p := view.Policy
	p.Enabled = true
	p.AllowedCIDRs = []string{"192.0.2.0/24"}
	if res, body := readingSave(t, c, "/api/v1/admin-access", p, readingHeaders(headers)); res.StatusCode != 422 || !strings.Contains(body, "ADMIN_SELF_LOCKOUT") {
		t.Fatal("self lockout", res.StatusCode, body)
	}
	p.AllowedCIDRs = []string{"127.0.0.0/8", "::1/128"}
	p.DeniedAgents = []string{"blocked-agent"}
	if res, body := readingSave(t, c, "/api/v1/admin-access", p, readingHeaders(headers)); res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	for _, path := range []string{"/login", "/", "/api/v1/admin-access", "/web/assets/ui.css"} {
		res, body := c.request("GET", path, "", http.Header{"User-Agent": {"blocked-agent"}, "X-Forwarded-For": {"127.0.0.1"}})
		if res.StatusCode != 403 || res.Header.Get("Cache-Control") != "no-store" || strings.Contains(body, "password") {
			t.Fatal("admin preauth", path, res.StatusCode, body)
		}
	}
	if res, _ := c.request("GET", "/login", "", nil); res.StatusCode != 200 {
		t.Fatal("allowed login")
	}
	c.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if repo.checkReading("admin", netip.MustParseAddr("192.0.2.1"), "") == nil {
		t.Fatal("admin persistence")
	}
	if err := repo.ResetAdminReadingAccess(); err != nil {
		t.Fatal(err)
	}
	if repo.checkReading("admin", netip.MustParseAddr("192.0.2.1"), "") != nil {
		t.Fatal("reset")
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c = newAdminClient(t, repo)
	if c.login(adminTestSecret) != 303 {
		t.Fatal("password changed")
	}
}

func TestReadingHTMLRetainsInvalidInput(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page := c.request("GET", "/reading", "", nil)
	f := pageFields(page)
	// pageFieldsはselect/textareaを抽出しないため、実フォームの値を補う。
	f.Set("allow_local_ip", "inherit")
	f.Set("allow_loopback_ip", "inherit")
	f.Set("enabled", "true")
	f.Set("japan_only", "true")
	f.Set("allow_vpn", "false")
	f.Set("deny_unresolved", "false")
	f.Set("deny_crawlers", "true")
	f.Set("allowed_cidrs", "bad-ip")
	f.Set("denied_cidrs", "")
	f.Set("denied_agents", "keep-agent")
	f.Set("denied_countries", "INVALID")
	for _, kind := range permissionKinds {
		f.Del("allow_" + kind.Value)
	}
	f.Set("allow_fixed", "true")
	res, body := c.request("POST", "/reading", f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 422 || !strings.Contains(body, "bad-ip") || !strings.Contains(body, "keep-agent") || !strings.Contains(body, "INVALID") || !strings.Contains(body, `value="true" selected>日本のみ許可`) {
		t.Fatal("retained input", res.StatusCode, body)
	}
	// 同名の制御値を複数送った入力を拒否する。
	f.Add("enabled", "false")
	if res, _ := c.request("POST", "/reading", f.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 400 {
		t.Fatal("duplicate", res.StatusCode)
	}
}

func TestReadingStrictPolicyValues(t *testing.T) {
	p := defaultReadingPolicy()
	raw, _ := json.Marshal(p)
	for _, invalid := range []string{strings.Replace(string(raw), `"enabled":false`, `"enabled":false,"enabled":true`, 1), strings.Replace(string(raw), `"allowed_cidrs":[]`, `"allowed_cidrs":null`, 1), strings.Replace(string(raw), `"enabled":false,`, "", 1), strings.Replace(string(raw), `"enabled":false`, `"enabled":"false"`, 1)} {
		if validateReadingValue("site", []byte(invalid)) == nil {
			t.Fatal("accepted", invalid)
		}
	}
	p.AllowedCIDRs = []string{"192.0.2.7/24"}
	if _, err := compileReadingPolicy(p); err == nil {
		t.Fatal("noncanonical CIDR")
	}
	p.AllowedCIDRs = []string{}
	p.DeniedAgents = []string{"agent", "AGENT"}
	if _, err := compileReadingPolicy(p); err == nil {
		t.Fatal("duplicate UA")
	}
	if validateReadingValue("missing-board", raw) == nil {
		t.Fatal("invalid scope")
	}
}

func TestReadingDoesNotGrantPostingCAPExemption(t *testing.T) {
	p := defaultReadingPolicy()
	p.Enabled = true
	p.Network.DeniedKinds = []string{"unknown"}
	v, err := compileReadingPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if v.check(nil, netip.MustParseAddr("192.0.2.1"), "") == nil {
		t.Fatal("unknown bypass")
	}
	p.Network.DeniedKinds = []string{}
	p.Network.JapanOnly = true
	v, _ = compileReadingPolicy(p)
	if v.check(nil, netip.MustParseAddr("192.0.2.1"), "") == nil {
		t.Fatal("unavailable country bypass")
	}
	p.Network.JapanOnly = false
	p.Network.AllowVPN = false
	v, _ = compileReadingPolicy(p)
	if v.check(nil, netip.MustParseAddr("192.0.2.1"), "") == nil {
		t.Fatal("unavailable vpn bypass")
	}
}

func TestReadingDenialAlsoDeniesPostingAndReplay(t *testing.T) {
	_, repo := adminFixture(t)
	useHealthyPostingCapacity(t, repo)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "readingpost", "閲覧と投稿")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID, true)
	defer form.Close()
	fields := url.Values{"bbs": {"readingpost"}, "subject": {"閲覧制限前の投稿"}, "MESSAGE": {"投稿本文"}, "oimo_request_id": {"reading-post-before-deny"}}
	first, err := sendForm(form, fields)
	if err != nil || !first.Accepted {
		t.Fatal(first, err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	if c.reauth(adminTestSecret) != 200 {
		t.Fatal("reauth")
	}
	cap, secret := createTestCap(t, repo, c, board.ID, []string{"create", "post"})
	capFields := url.Values{}
	for name, values := range fields {
		capFields[name] = append([]string{}, values...)
	}
	capFields.Set("key", strconv.FormatUint(first.Key, 10))
	capFields.Del("subject")
	capFields.Set("mail", "#cap:"+cap.ID.String()+":"+secret)
	capFields.Set("oimo_request_id", "reading-cap-before-deny")
	if accepted, err := sendForm(form, capFields); err != nil || !accepted.Accepted {
		t.Fatal("valid CAP setup", accepted, err)
	}
	route := "/api/v1/boards/" + board.ID.String() + "/reading"
	view, h := readingGet(t, c, route)
	p := view.Policy
	p.Enabled = true
	p.DeniedCIDRs = []string{"127.0.0.0/8", "::1/128"}
	if res, body := readingSave(t, c, route, p, readingHeaders(h)); res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	for _, id := range []string{"reading-post-before-deny", "reading-post-new-denied"} {
		fields.Set("oimo_request_id", id)
		denied, err := sendForm(form, fields)
		if err != nil || denied.Accepted || denied.Confirmation != nil {
			t.Fatal("form bypass", id, denied, err)
		}
	}
	for _, id := range []string{"reading-cap-before-deny", "reading-cap-new-denied"} {
		capFields.Set("oimo_request_id", id)
		if denied, err := sendForm(form, capFields); err != nil || denied.Accepted || denied.Confirmation != nil {
			t.Fatal("CAP bypass", denied, err)
		}
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "reading-cgi-test")
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	public.Config.ConnContext = observer.ConnContext
	public.Start()
	defer public.Close()
	public.Client().Jar = form.Client().Jar
	request, err := http.NewRequest("POST", public.URL+"/test/bbs.cgi", strings.NewReader(fields.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "127.0.0.1:9080"
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	response, err := public.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("real CGI bypass", response.StatusCode)
	}
	req := httptest.NewRequest("POST", repo.cfg.Public.BaseURL+"/web/post?bbs=readingpost", strings.NewReader(fields.Encode()))
	req.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	repo.WebPostingHandler(board.ID, nil).ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal("web post bypass", w.Code)
	}
}

func TestReadingPostingRestrictionDoesNotDenyReads(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "postonly", "投稿のみ禁止")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, row := c.board(board.ID.String())
	row.Settings.Create = "disabled"
	row.Settings.Reply = "disabled"
	raw, _ := json.Marshal(row.Settings)
	saved, body := c.request("PATCH", "/api/v1/boards/"+board.ID.String()+"/settings", string(raw), readingHeaders(res.Header))
	if saved.StatusCode != 200 {
		t.Fatal(saved.StatusCode, body)
	}
	if w := publicLocalRules(t, repo, "/postonly/subject.txt", nil); w.Code != 200 {
		t.Fatal("posting disabled blocks reading", w.Code)
	}
}

func TestReadingStreamingAndLeaseCheckBoundary(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+"/", nil)
	req.RemoteAddr = "192.0.2.1:12345"
	base := httptest.NewRecorder()
	writer, denied := repo.readingGate(base, req, "site")
	if denied {
		t.Fatal("initial")
	}
	p := defaultReadingPolicy()
	p.Enabled = true
	p.DeniedCIDRs = []string{"192.0.2.0/24"}
	compiled, _ := compileReadingPolicy(p)
	repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"site": compiled}})
	n, err := writer.(interface {
		WriteResponse(int, []byte) (int, error)
	}).WriteResponse(206, []byte("private body"))
	if err == nil || n != 0 || base.Code != 403 || base.Body.Len() != 0 {
		t.Fatal("revoked before header", base.Code, n, err)
	}
	base = httptest.NewRecorder()
	leaseErr := errors.New("deleted publication")
	writer = &readingResponse{ResponseWriter: base, check: func() error { return nil }}
	_, err = writer.(interface {
		WriteResponseChecked(int, []byte, func() error) (int, error)
	}).WriteResponseChecked(200, []byte("deleted"), func() error { return leaseErr })
	if !errors.Is(err, leaseErr) || base.Body.Len() != 0 || base.Code == 403 {
		t.Fatal("lease rejection became reading denial", err, base.Code)
	}
}

func TestReadingScopedBoardAdministrator(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "scopeview", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "scopeoutside", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.CreateAdministrator("readeradmin", "板管理者", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{board.ID}, Permissions: []string{}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "readeradmin")
	fields.Set("password", adminTestSecret)
	if res, body := c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); res.StatusCode != 303 {
		t.Fatal("scoped login", res.StatusCode, body)
	}
	route := "/api/v1/boards/" + board.ID.String() + "/reading"
	v, h := readingGet(t, c, route)
	v.Policy.Enabled = true
	v.Policy.DeniedCIDRs = []string{"192.0.2.0/24"}
	if res, body := readingSave(t, c, route, v.Policy, readingHeaders(h)); res.StatusCode != 200 {
		t.Fatal("scoped save", res.StatusCode, body)
	}
	for _, path := range []string{"/reading", "/admin-access", "/api/v1/reading", "/api/v1/admin-access", "/boards/" + other.ID.String() + "/reading", "/api/v1/boards/" + domain.NewID().String() + "/reading"} {
		if res, body := c.request("GET", path, "", nil); res.StatusCode != 403 || strings.Contains(body, "担当外") {
			t.Fatal("scope bypass", path, res.StatusCode, body)
		}
	}
}

func TestReadingManagementPageFixture(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	res, body := c.request("GET", "/admin-access", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "reset-reading-access") || !strings.Contains(body, "管理画面のアクセス制限") {
		t.Fatal("admin page", res.StatusCode)
	}
	if strings.Contains(body, `<select name="deny_crawlers"`) || strings.Count(body, `name="deny_crawlers"`) != 1 || strings.Count(body, "data-fixed-protection") != 3 || !strings.Contains(body, "OFF：追加制限を使わない") {
		t.Fatal("fixed admin protections must not appear editable")
	}
	if path := os.Getenv("OIMO_READING_PAGE_OUTPUT"); path != "" {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
