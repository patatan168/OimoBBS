// 案件の共通ページ送りを実HTTPと署名済み案件で検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

type evidenceListReply struct {
	Data     []disclosure.Case      `json:"data"`
	Dates    []evidenceCaseHTTPView `json:"dates"`
	Total    int                    `json:"total"`
	Limit    int                    `json:"limit"`
	Next     string                 `json:"next_cursor"`
	Revision string                 `json:"revision"`
	Tokens   map[string]string      `json:"csrf_tokens"`
}

// evidenceListFixture は51件の担当内案件と1件の担当外案件を実保存する。
func evidenceListFixture(t *testing.T) (*Repository, *adminClient, disclosure.Case) {
	t.Helper()
	cfg, repo := adminFixture(t)
	board, err := repo.CreateBoard(t.Context(), "pages", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	other, err := repo.CreateBoard(t.Context(), "other", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := repo.CreateAdministrator("case.reader", "案件閲覧", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{board.ID}, Permissions: []string{"evidence.manage"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { repo.Close() })
	if _, err = repo.enableStorageReader(t.Context(), 38, "evidence_case_enable"); err != nil {
		t.Fatal(err)
	}
	hidden := createEvidenceListCases(t, repo, admin.ID, board.ID, other.ID)
	c := newAdminClient(t, repo)
	t.Cleanup(c.server.Close)
	if loginEvidenceListReader(c) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	return repo, c, hidden
}

func loginEvidenceListReader(c *adminClient) int {
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "case.reader")
	fields.Set("password", adminTestSecret)
	res, _ := c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	return res.StatusCode
}

// createEvidenceListCases は所有者の排他下で実署名案件を保存する。
func createEvidenceListCases(t *testing.T, repo *Repository, actor, board, other domain.ID) disclosure.Case {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	now := time.Now().Add(-time.Minute)
	var hidden disclosure.Case
	for i := range 52 {
		owner := board
		if i == 51 {
			owner = other
		}
		input := disclosure.Case{Number: fmt.Sprintf("CASE%03d", i), Reason: "一覧検査", Scope: disclosure.Scope{Board: owner, From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}}
		if i == 7 {
			input.Reason += " 特別理由"
			input.Organization = "照会機関"
			input.Reference = "REF-Seven"
			input.Scope.Thread = 123450007
		}
		created, err := repo.evidenceCases.Create(input, actor, `"evidence:new"`, fmt.Sprintf("list-case-create-%04d", i), now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if i == 51 {
			hidden = created
		}
	}
	return hidden
}

func readEvidenceList(t *testing.T, c *adminClient, path string) evidenceListReply {
	t.Helper()
	res, body := c.request("GET", path, "", nil)
	var reply evidenceListReply
	if res.StatusCode != 200 || json.Unmarshal([]byte(body), &reply) != nil {
		t.Fatal(res.StatusCode, body)
	}
	if len(reply.Data) != len(reply.Dates) {
		t.Fatal("dates outside page")
	}
	for i, row := range reply.Data {
		if reply.Dates[i].ID != row.ID {
			t.Fatal("date binding")
		}
	}
	return reply
}

func TestAdminEvidenceListPaginationAndScope(t *testing.T) {
	repo, c, hidden := evidenceListFixture(t)
	first := readEvidenceList(t, c, "/api/v1/evidence/cases")
	if len(first.Data) != 50 || first.Limit != 50 || first.Next == "" {
		t.Fatal("default page")
	}
	last := readEvidenceList(t, c, "/api/v1/evidence/cases?"+url.Values{"cursor": {first.Next}}.Encode())
	if len(last.Data) != 1 || last.Limit != 50 || last.Next != "" || last.Data[0].Created >= first.Data[49].Created {
		t.Fatal("continuation")
	}
	all := readEvidenceList(t, c, "/api/v1/evidence/cases?limit=200")
	assertEvidenceListScope(t, all, hidden.ID)
	assertEvidencePageTokens(t, first, last.Data[0].ID)
	assertEvidenceListCursorChanges(t, repo, c, first, hidden)
}

func assertEvidenceListScope(t *testing.T, reply evidenceListReply, hidden domain.ID) {
	t.Helper()
	if len(reply.Data) != 51 || reply.Next != "" || reply.Limit != 200 {
		t.Fatal("maximum page")
	}
	for _, c := range reply.Data {
		if c.ID == hidden {
			t.Fatal("hidden case disclosed")
		}
	}
}

func assertEvidencePageTokens(t *testing.T, reply evidenceListReply, outside domain.ID) {
	t.Helper()
	for route := range reply.Tokens {
		if strings.Contains(route, outside.String()) {
			t.Fatal("off-page action token", route)
		}
	}
	if _, ok := reply.Tokens["/api/v1/evidence/cases/"+reply.Data[0].ID.String()+"/hold"]; !ok {
		t.Fatal("page action token missing")
	}
}

// assertEvidenceListCursorChanges は担当外の更新で継続でき、担当内更新で失効することを検査する。
func assertEvidenceListCursorChanges(t *testing.T, repo *Repository, c *adminClient, first evidenceListReply, hidden disclosure.Case) {
	t.Helper()
	extendEvidenceListCase(t, repo, hidden, "hidden-case-extend-01")
	path := "/api/v1/evidence/cases?" + url.Values{"cursor": {first.Next}}.Encode()
	continued := readEvidenceList(t, c, path)
	if continued.Revision != first.Revision {
		t.Fatal("hidden update changed list version")
	}
	visible := first.Data[0]
	extendEvidenceListCase(t, repo, visible, "visible-case-extend-01")
	res, _ := c.request("GET", path, "", nil)
	if res.StatusCode != 409 {
		t.Fatal("changed version accepted", res.StatusCode)
	}
}

func extendEvidenceListCase(t *testing.T, repo *Repository, c disclosure.Case, key string) {
	t.Helper()
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if _, err := repo.evidenceCases.Extend(c.ID, c.Creator, c.ETag(), key, "期限変更", c.Until+domain.Time(time.Hour), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestAdminEvidenceListHTMLAndQueries(t *testing.T) {
	_, c, hidden := evidenceListFixture(t)
	first := readEvidenceList(t, c, "/api/v1/evidence/cases?limit=1")
	res, page := c.request("GET", "/evidence?limit=1", "", nil)
	nextRE := regexp.MustCompile(`<a href="([^"]+)">次の案件</a>`)
	match := nextRE.FindStringSubmatch(page)
	if res.StatusCode != 200 || len(match) != 2 || !strings.Contains(page, first.Data[0].ID.String()) || strings.Contains(page, hidden.ID.String()) {
		t.Fatal(res.StatusCode, page)
	}
	if strings.Count(page, `class="evidence-case"`) != 1 || !strings.Contains(page, `class="evidence-case-summary"`) || !strings.Contains(page, "担当板") || !strings.Contains(page, "/pages/") {
		t.Fatal("compact case summary missing")
	}
	if strings.Contains(page, `class="evidence-case" open`) || strings.Contains(page, `id="new-case" open`) {
		t.Fatal("case details or creation form expanded by default")
	}
	next := html.UnescapeString(match[1])
	res, page = c.request("GET", next, "", nil)
	if res.StatusCode != 200 || strings.Contains(page, first.Data[0].ID.String()) {
		t.Fatal("HTML continuation", res.StatusCode, page)
	}
	assertEvidenceInvalidListQueries(t, c, first, next)
}

func assertEvidenceInvalidListQueries(t *testing.T, c *adminClient, first evidenceListReply, htmlNext string) {
	t.Helper()
	for _, path := range []string{
		"/api/v1/evidence/cases?limit=201", "/evidence?limit=0", "/evidence?unknown=1",
		"/api/v1/evidence/cases?limit=1&limit=1",
		"/evidence?" + url.Values{"cursor": {first.Next}}.Encode(),
		"/api/v1/evidence/cases?" + strings.SplitN(htmlNext, "?", 2)[1],
	} {
		res, _ := c.request("GET", path, "", nil)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatal("invalid query accepted", path, res.StatusCode)
		}
	}
	res, _ := c.request("GET", "/api/v1/evidence/cases/"+first.Data[0].ID.String()+"?limit=1", "", nil)
	if res.StatusCode != http.StatusForbidden {
		t.Fatal("detail query passed admin boundary", res.StatusCode)
	}
}

// TestAdminEvidenceSearchAndOrder はページ外の検索、並び順、担当外の非表示を実HTTPで確認する。
func TestAdminEvidenceSearchAndOrder(t *testing.T) {
	_, c, _ := evidenceListFixture(t)
	newest := readEvidenceList(t, c, "/api/v1/evidence/cases?limit=2")
	if newest.Total != 51 || newest.Data[0].Number != "CASE050" || newest.Data[1].Number != "CASE049" {
		t.Fatal("newest order", newest)
	}
	for _, query := range []string{"CASE000", "特別理由", "照会機関", "ref-seven", "123450007", "pages CASE007", "担当板 CASE007"} {
		reply := readEvidenceList(t, c, "/api/v1/evidence/cases?"+url.Values{"q": {query}}.Encode())
		want := "CASE007"
		if query == "CASE000" {
			want = query
		}
		if len(reply.Data) != 1 || reply.Total != 1 || reply.Data[0].Number != want {
			t.Fatal("search", query, reply)
		}
	}
	for _, sort := range []string{"oldest", "until"} {
		reply := readEvidenceList(t, c, "/api/v1/evidence/cases?sort="+sort+"&limit=2")
		if len(reply.Data) != 2 || reply.Data[0].Number != "CASE000" || reply.Data[1].Number != "CASE001" {
			t.Fatal("order", sort, reply)
		}
	}
	for _, values := range []url.Values{{"q": {"担当外"}}, {"q": {"CASE051"}}, {"q": {"CASE000 absent"}}, {"state": {"active"}}} {
		reply := readEvidenceList(t, c, "/api/v1/evidence/cases?"+values.Encode())
		if reply.Total != 0 || len(reply.Data) != 0 || reply.Next != "" {
			t.Fatal("empty or hidden results leaked", values, reply)
		}
	}
	values := url.Values{"q": {"CASE"}, "state": {"draft"}, "sort": {"oldest"}, "limit": {"2"}}
	first := readEvidenceList(t, c, "/api/v1/evidence/cases?"+values.Encode())
	if first.Total != 51 || first.Next == "" {
		t.Fatal("filtered first page")
	}
	values.Set("cursor", first.Next)
	next := readEvidenceList(t, c, "/api/v1/evidence/cases?"+values.Encode())
	if next.Data[0].Number != "CASE002" {
		t.Fatal("filtered continuation", next)
	}
	for name, value := range map[string]string{"q": "case", "state": "", "sort": "newest"} {
		bad := url.Values{}
		for k, v := range values {
			bad[k] = append([]string{}, v...)
		}
		bad.Set(name, value)
		res, _ := c.request("GET", "/api/v1/evidence/cases?"+bad.Encode(), "", nil)
		if res.StatusCode != 400 {
			t.Fatal("changed filter accepted", name, res.StatusCode)
		}
	}
	assertEvidenceSearchHTML(t, c)
}

func assertEvidenceSearchHTML(t *testing.T, c *adminClient) {
	t.Helper()
	values := url.Values{"q": {"CASE"}, "state": {"draft"}, "sort": {"oldest"}, "limit": {"1"}}
	res, page := c.request("GET", "/evidence?"+values.Encode(), "", nil)
	match := regexp.MustCompile(`<a href="([^"]+)">次の案件</a>`).FindStringSubmatch(page)
	if res.StatusCode != 200 || len(match) != 2 || !strings.Contains(page, "作成日時の古い順") || !strings.Contains(page, "51件中 1–1件") || !strings.Contains(page, `value="CASE"`) || !regexp.MustCompile(`作成 \d{4}-`).MatchString(page) {
		t.Fatal("search page", res.StatusCode, page)
	}
	next, err := url.Parse(html.UnescapeString(match[1]))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"q", "state", "sort"} {
		if next.Query().Get(name) != values.Get(name) {
			t.Fatal("lost search condition", name, next)
		}
	}
	res, page = c.request("GET", next.String(), "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "51件中 2–2件") {
		t.Fatal("search HTML continuation", res.StatusCode, page)
	}
	res, page = c.request("GET", "/evidence?q=not-found", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, "条件に一致する案件はありません") || strings.Contains(page, `id="new-case" open`) || !strings.Contains(page, `value="not-found"`) {
		t.Fatal("empty search", res.StatusCode, page)
	}
	for _, query := range []string{"sort=invalid", "state=unknown", "q=a&q=b", "sort=newest&sort=oldest", "state=draft&state=draft", "q=" + strings.Repeat("a", 129), "q=a+b+c+d+e+f+g+h+i"} {
		res, _ := c.request("GET", "/evidence?"+query, "", nil)
		if res.StatusCode != 400 {
			t.Fatal("invalid filter accepted", query, res.StatusCode)
		}
	}
}

func TestEvidenceSortTies(t *testing.T) {
	a, b := disclosure.Case{ID: domain.NewID(), Created: 100, Until: 300}, disclosure.Case{ID: domain.NewID(), Created: 100, Until: 200}
	for _, sort := range []string{"newest", "oldest", "until"} {
		f := evidenceListFilter{Sort: sort}
		n := f.compare(a, b)
		if n == 0 || n != -f.compare(b, a) {
			t.Fatal("unstable tie", sort)
		}
		if sort == "until" && n < 0 {
			t.Fatal("until order")
		}
	}
}

// TestAdminEvidenceSearchBrowser は実際のログイン・検索フォーム・ページ送りを画面で検査する。
func TestAdminEvidenceSearchBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザー検証を有効化")
	}
	repo, _, _ := evidenceListFixture(t)
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	origin := "http://localhost:" + strings.Split(server.Listener.Addr().String(), ":")[1]
	repo.cfg.Admin.Transport, repo.cfg.Admin.Origin, repo.cfg.Public.BaseURL = "public_path", origin+"/admin", origin
	admin, err := repo.AdminHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = admin.Handler
	server.Start()
	script, err := filepath.Abs("../../scripts/test-admin-evidence-search-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_EVIDENCE_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}
