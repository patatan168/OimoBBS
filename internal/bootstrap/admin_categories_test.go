// 板カテゴリーの管理操作、公開分類、競合・再送・復旧を実HTTPで検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
)

func TestBoardCategoriesHTTPRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	alpha, err := repo.CreateBoard(t.Context(), "alpha", "A板")
	if err != nil {
		t.Fatal(err)
	}
	_, err = repo.CreateBoard(t.Context(), "beta", "B板")
	if err != nil {
		t.Fatal(err)
	}
	oldMenuETag := publicLocalRules(t, repo, "/bbsmenu.json", nil).Header().Get("ETag")
	before := append([]byte{}, publicLocalRules(t, repo, "/alpha/dat/1.dat", nil).Body.Bytes()...)
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	res, _ := client.request("GET", "/board-categories", "", nil)
	if res.StatusCode != 401 {
		t.Fatal("unauth", res.StatusCode)
	}
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	getFields := func() url.Values {
		t.Helper()
		res, body := client.request("GET", "/board-categories", "", nil)
		if res.StatusCode != 200 || !strings.Contains(body, "板のカテゴリー") || !strings.Contains(body, "alpha") {
			t.Fatal("page", res.StatusCode, body)
		}
		all := pageFields(body)
		return url.Values{"csrf": {all.Get("csrf")}, "revision": {all.Get("revision")}, "request_id": {all.Get("request_id")}}
	}
	post := func(fields url.Values, want int) string {
		t.Helper()
		res, body := client.request("POST", "/board-categories", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		if res.StatusCode != want {
			t.Fatal("save", fields.Get("action"), res.StatusCode, body)
		}
		return body
	}
	save := func(action, category, board, name, position string) url.Values {
		t.Helper()
		fields := getFields()
		fields.Set("action", action)
		fields.Set("category", category)
		fields.Set("board", board)
		fields.Set("name", name)
		fields.Set("position", position)
		post(fields, 303)
		return fields
	}
	view := func() boardCategories {
		t.Helper()
		repo.mu.Lock()
		defer repo.mu.Unlock()
		v, e := repo.boardCategoriesLocked()
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	original := getFields()
	original.Set("action", "add")
	original.Set("name", "話題 <&>")
	invalid := original.Clone()
	invalid.Set("csrf", "invalid")
	post(invalid, 403)
	post(original, 303)
	// 同じ要求の再送はカテゴリーを重複追加しない。
	post(original, 303)
	if len(view().Categories) != 1 {
		t.Fatal("duplicate")
	}
	conflict := original.Clone()
	conflict.Set("name", "別名")
	post(conflict, 409)
	stale := getFields()
	first := view().Categories[0].ID.String()
	save("add", "", "", "交流", "")
	second := view().Categories[1].ID.String()
	stale.Set("action", "rename")
	stale.Set("category", first)
	stale.Set("name", "古い画面")
	post(stale, 412)
	duplicate := getFields()
	duplicate.Set("action", "rename")
	duplicate.Set("category", first)
	duplicate.Set("name", "交流")
	if !strings.Contains(post(duplicate, 422), `value="交流"`) {
		t.Fatal("input not retained")
	}
	invalidBoard := getFields()
	invalidBoard.Set("action", "assign")
	invalidBoard.Set("board", "missing")
	invalidBoard.Set("category", first)
	post(invalidBoard, 422)
	malformed := getFields()
	malformed.Set("action", "add")
	malformed.Set("name", "unknown")
	malformed.Set("unknown", "true")
	post(malformed, 400)
	duplicated := getFields()
	duplicated.Set("action", "add")
	duplicated.Set("name", "duplicate")
	duplicated.Add("name", "second")
	post(duplicated, 400)
	save("assign", first, "alpha", "", "")
	save("assign", second, "beta", "", "")
	save("move", second, "", "", "1")
	menu := publicLocalRules(t, repo, "/bbsmenu.json", http.Header{"If-None-Match": {oldMenuETag}})
	if menu.Code != 200 {
		t.Fatal("stale menu conditional", menu.Code)
	}
	var parsed struct {
		List []legacyCategory `json:"menu_list"`
	}
	if json.Unmarshal(menu.Body.Bytes(), &parsed) != nil || len(parsed.List) != 2 || parsed.List[0].Name != "交流" || !strings.HasSuffix(parsed.List[0].Boards[0].URL, "/beta/") {
		t.Fatal("JSON categories", menu.Body.String())
	}
	htmlMenu := publicLocalRules(t, repo, "/bbsmenu.html", nil)
	decoded, err := textcodec.Decode(htmlMenu.Body.Bytes())
	if err != nil || !strings.Contains(decoded, "話題 &lt;&amp;&gt;") || strings.Index(decoded, "交流") > strings.Index(decoded, "話題") {
		t.Fatal("HTML categories", decoded, err)
	}
	root := publicLocalRules(t, repo, "/", nil).Body.String()
	if !strings.Contains(root, "話題 &lt;&amp;&gt;") || strings.Index(root, "交流") > strings.Index(root, "話題") {
		t.Fatal("root categories", root)
	}
	save("rename", first, "", "雑談", "")
	if !bytes.Equal(before, publicLocalRules(t, repo, "/alpha/dat/1.dat", nil).Body.Bytes()) {
		t.Fatal("DAT changed")
	}
	if publicLocalRules(t, repo, "/board-categories", nil).Code != 404 {
		t.Fatal("public admin leak")
	}
	var state siteState
	if strictjson.Decode(repo.site.State().Rows["site:state"].Value, &state) != nil || state.MinimumReader < 77 {
		t.Fatal("reader")
	}
	client.server.Close()
	if repo.Close() != nil {
		t.Fatal("close")
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("recovery", err)
	}
	client = newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	if view().Categories[1].Name != "雑談" {
		t.Fatal("category recovery")
	}
	_, boards, err := repo.webBoards()
	if err != nil {
		t.Fatal(err)
	}
	for _, board := range boards {
		if board.ID == alpha.ID && board.CategoryName != "雑談" {
			t.Fatal("assignment recovery")
		}
	}
	same, err := repo.CreateBoard(t.Context(), "alpha", "A板")
	if err != nil || same.ID != alpha.ID {
		t.Fatal("existing categorized board", same, err)
	}
	// 新板は未分類。カテゴリー削除は割当だけを外し、板・DATを残す。
	_, err = repo.CreateBoard(t.Context(), "gamma", "C板")
	if err != nil {
		t.Fatal(err)
	}
	save("delete", first, "", "", "")
	root = publicLocalRules(t, repo, "/", nil).Body.String()
	if !strings.Contains(root, "未分類") || !strings.Contains(root, "alpha") || !strings.Contains(root, "gamma") {
		t.Fatal("unassigned", root)
	}
	save("assign", "", "beta", "", "")
	if !bytes.Equal(before, publicLocalRules(t, repo, "/alpha/dat/1.dat", nil).Body.Bytes()) {
		t.Fatal("delete changed DAT")
	}
}

func TestBoardCategoriesPermissionAndValidation(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	if _, err := repo.CreateAdministrator("boardowner", "板担当", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{}, Permissions: []string{}, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	_, page := c.request("GET", "/login", "", nil)
	fields := pageFields(page)
	fields.Set("login", "boardowner")
	fields.Set("password", adminTestSecret)
	res, _ := c.request("POST", "/login", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("role login")
	}
	for _, method := range []string{"GET", "POST"} {
		res, _ = c.request(method, "/board-categories", "", nil)
		if res.StatusCode != 403 {
			t.Fatal("role access", res.StatusCode)
		}
	}
}

func TestBoardCategoriesReaderAndReferences(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "alpha", "A板")
	if err != nil {
		t.Fatal(err)
	}
	state := repo.site.State()
	state.Rows = maps.Clone(state.Rows)
	var site siteState
	siteRow := state.Rows["site:state"]
	if err := strictjson.Decode(siteRow.Value, &site); err != nil {
		t.Fatal(err)
	}
	name := "board_directory:" + board.ID.String()
	row := state.Rows[name]
	var directory boardDirectory
	if strictjson.Decode(row.Value, &directory) != nil {
		t.Fatal("directory")
	}
	original := append([]byte{}, row.Value...)
	id := domain.NewID()
	directory.CategoryID = &id
	row.Value, _ = json.Marshal(directory)
	state.Rows[name] = row
	site.MinimumReader = 77
	siteRow.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = siteRow
	if _, err = siteDirectories(state); err == nil {
		t.Fatal("orphan category allowed")
	}
	site.Categories = []category{{ID: id, Name: "分類", Order: 0}}
	site.MinimumReader = 76
	siteRow.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = siteRow
	if _, err = siteDirectories(state); err == nil {
		t.Fatal("old reader allowed")
	}
	site.MinimumReader = 77
	siteRow.Value, _ = json.Marshal(site)
	state.Rows["site:state"] = siteRow
	if _, err = siteDirectories(state); err != nil {
		t.Fatal("valid category rejected", err)
	}
	if validateDirectory(board.ID.String(), original, row.Value) != nil {
		t.Fatal("active assignment rejected")
	}
	directory.JobID = domain.NewID()
	invalid, _ := json.Marshal(directory)
	if validateDirectory(board.ID.String(), original, invalid) == nil {
		t.Fatal("job change allowed")
	}
	directory.Status = "provisioning"
	invalid, _ = json.Marshal(directory)
	if validateDirectory(board.ID.String(), nil, invalid) == nil {
		t.Fatal("initial assignment allowed")
	}
}

// TestBoardCategoriesLargePage は上限件数の表示と保存失敗時の展開・入力保持を検証する。
func TestBoardCategoriesLargePage(t *testing.T) {
	page := categoriesPage{Values: url.Values{}}
	for i := range 256 {
		id := domain.NewID()
		page.View.Categories = append(page.View.Categories, category{ID: id, Name: fmt.Sprintf("カテゴリー%03d", i), Order: uint32(i)})
		if i < 128 {
			page.View.Boards = append(page.View.Boards, categoryBoard{ID: domain.NewID(), Key: fmt.Sprintf("board%03d", i), Name: fmt.Sprintf("板%03d", i), Category: id.String()})
		}
	}
	var body bytes.Buffer
	if err := categoriesTemplate.Execute(&body, page); err != nil {
		t.Fatal(err)
	}
	html := body.String()
	if strings.Count(html, "<li data-filter-text=") != 384 || strings.Contains(html, "<details open") || !strings.Contains(html, "127. カテゴリー126") || !strings.Contains(html, "（0板）") || !strings.Contains(html, `data-filter-text="板127 board127 カテゴリー127"`) {
		t.Fatalf("large page summaries: count=%d open=%t position=%t empty=%t filter=%t", strings.Count(html, "<li data-filter-text="), strings.Contains(html, "<details open"), strings.Contains(html, "127. カテゴリー126"), strings.Contains(html, "（0板）"), strings.Contains(html, `data-filter-text="板127 board127 カテゴリー127"`))
	}
	// 指定時だけブラウザ用の架空データを出力する。稼働中の分類は変更しない。
	if output := os.Getenv("OIMO_CATEGORY_UI_FIXTURE"); output != "" {
		if err := os.WriteFile(output, body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
	page.Values = url.Values{"action": {"rename"}, "category": {page.View.Categories[127].ID.String()}, "name": {"修正 <&>"}}
	body.Reset()
	if err := categoriesTemplate.Execute(&body, page); err != nil {
		t.Fatal(err)
	}
	if strings.Count(body.String(), "<details open") != 1 || !strings.Contains(body.String(), `value="修正 &lt;&amp;&gt;"`) {
		t.Fatal("failed rename hidden or lost")
	}
	page.Values = url.Values{"action": {"assign"}, "board": {"board127"}, "category": {""}}
	body.Reset()
	if err := categoriesTemplate.Execute(&body, page); err != nil {
		t.Fatal(err)
	}
	if strings.Count(body.String(), "<details open") != 1 || !strings.Contains(body.String(), `<option value="" selected>未分類`) {
		t.Fatal("failed assignment hidden or lost")
	}
	page.Values.Set("category", page.View.Categories[0].ID.String())
	body.Reset()
	if err := categoriesTemplate.Execute(&body, page); err != nil {
		t.Fatal(err)
	}
	if strings.Count(body.String(), "<details open") != 1 {
		t.Fatal("assignment opened unrelated category")
	}
}
