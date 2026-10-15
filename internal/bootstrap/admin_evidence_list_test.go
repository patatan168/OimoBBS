// 案件の共通ページ送りを実HTTPと署名済み案件で検査する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
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
	now := time.Now()
	var hidden disclosure.Case
	for i := range 52 {
		owner := board
		if i == 51 {
			owner = other
		}
		input := disclosure.Case{Number: fmt.Sprintf("CASE%03d", i), Reason: "一覧検査", Scope: disclosure.Scope{Board: owner, From: domain.Time(now.Add(-time.Hour).UnixNano()), To: domain.Time(now.UnixNano())}}
		created, err := repo.evidenceCases.Create(input, actor, `"evidence:new"`, fmt.Sprintf("list-case-create-%04d", i), now)
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
	if len(last.Data) != 1 || last.Limit != 50 || last.Next != "" || last.Data[0].ID.String() <= first.Data[49].ID.String() {
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
