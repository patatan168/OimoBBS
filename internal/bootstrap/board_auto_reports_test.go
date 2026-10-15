// 板ごとの通報切替を管理HTTP・公開投稿・受付案内・再起動で検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
)

func TestBoardAutoReportsHTTPRecovery(t *testing.T) {
	cfg, repo, site, owner := anonymousFixture(t, "required")
	defer func() { repo.Close() }()
	other, err := repo.CreateBoard(t.Context(), "other", "別板")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.CreateBoard(t.Context(), "report", "通報"); err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ConfigureAdministrator("owner", "所有者", adminTestSecret, false); err != nil {
		t.Fatal(err)
	}
	repo.Close()
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	var admin *adminClient
	var public *httptest.Server
	start := func() {
		admin = newAdminClient(t, repo)
		if admin.login(adminTestSecret) != 303 {
			t.Fatal("login")
		}
		observer, err := evidence.NewHTTPObserver(site, domain.NewID(), "board-report-test")
		if err != nil {
			t.Fatal(err)
		}
		public = httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
		public.Config.ConnContext = observer.ConnContext
		public.Start()
	}
	start()
	defer func() { admin.server.Close(); public.Close() }()
	restart := func() {
		admin.server.Close()
		public.Close()
		repo.Close()
		repo, err = OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			t.Fatal("restart", err)
		}
		start()
	}
	save := func(value *bool) {
		t.Helper()
		res, row := admin.board(owner.String())
		row.Settings.AutoReportsEnabled = value
		raw, _ := json.Marshal(row.Settings)
		saved, body := admin.request("PATCH", "/api/v1/boards/"+owner.String()+"/settings", string(raw), http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}})
		if saved.StatusCode != 200 {
			t.Fatal("save", saved.StatusCode, body)
		}
	}
	voteCount := func(board domain.ID) int {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		count := 0
		for target, votes := range repo.autoReportVotes {
			if target.Board == board {
				count += len(votes)
			}
		}
		return count
	}
	denialCount := func(board domain.ID) int {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		value, err := repo.posting[board].worker.Submit(t.Context(), func() (any, error) { return len(repo.posting[board].denials), nil })
		if err != nil {
			t.Fatal(err)
		}
		return value.(int)
	}
	clientNumber := 0
	newReader := func() *autoReportHTTPClient {
		clientNumber++
		return newAutoReportHTTPClient(t, public.URL, cfg.Public.BaseURL, fmt.Sprintf("127.126.0.%d", clientNumber))
	}
	post := func(board, key, body string) {
		t.Helper()
		if result := newReader().post(t, board, key, body, domain.NewID().String()); !strings.Contains(result, "投稿を受け付けました") {
			t.Fatal("post", result)
		}
	}
	reader := newReader()
	post("news", "", "TARGET")
	post("other", "", "OTHER TARGET")
	key := strings.Split(reader.request(t, "/news/subject.txt", nil), ".dat<>")[0]
	otherKey := strings.Split(reader.request(t, "/other/subject.txt", nil), ".dat<>")[0]
	reference := "対象URL：" + cfg.Public.BaseURL + "/test/read.cgi/news/" + key + "/1/"
	post("news", key, ">>1 !report old vote")
	post("report", "1", reference)
	if voteCount(owner) != 2 {
		t.Fatal("initial public/private votes")
	}
	ids, err := reportFiles(cfg.DataDir)
	if err != nil || len(ids) != 1 {
		t.Fatal("private history", err)
	}
	before := publicLocalRules(t, repo, "/news/dat/1.dat", nil)
	off, on := false, true
	res, row := admin.board(owner.String())
	fields := adminBoardFields(row.Settings)
	fields.Set("auto_reports_enabled", "false")
	fields.Set("revision", res.Header.Get("ETag"))
	fields.Set("csrf", res.Header.Get("X-CSRF-Token"))
	fields.Set("request_id", domain.NewID().String())
	if saved, body := admin.request("POST", "/boards/"+owner.String()+"/settings", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}); saved.StatusCode != 303 {
		t.Fatal("HTML save", saved.StatusCode, body)
	}
	if voteCount(owner) != 0 {
		t.Fatal("old votes not cleared")
	}
	since := repo.posting[owner].autoReports.Load().Since
	save(nil)  // 旧APIが項目を省略しても無効状態を保持する。
	save(&off) // 同じ値で集計の開始時刻を更新しない。
	if settings := repo.posting[owner].autoReports.Load(); settings.Enabled || settings.Since != since {
		t.Fatal("omitted/no-op setting changed state")
	}
	res, page := admin.request("GET", "/boards/"+owner.String()+"/settings", "", nil)
	if res.StatusCode != 200 || !strings.Contains(page, `name="auto_reports_enabled"`) || !strings.Contains(page, `value="false" selected>無効`) {
		t.Fatal("admin UI state")
	}
	disabledGuide := publicLocalRules(t, repo, "/news/dat/1.dat", nil)
	if !strings.Contains(newReader().request(t, "/news/dat/1.dat", nil), "通報機能は現在無効") || before.Header().Get("ETag") == disabledGuide.Header().Get("ETag") {
		t.Fatal("disabled guide/ETag")
	}
	if body := newReader().post(t, "report", "1", reference, domain.NewID().String()); !strings.Contains(body, "通報機能は現在無効") {
		t.Fatal("central receipt bypass", body)
	}
	if body := newReader().post(t, "news", "1", reference, domain.NewID().String()); !strings.Contains(body, "通報機能は現在無効") {
		t.Fatal("board receipt bypass", body)
	}
	afterIDs, err := reportFiles(cfg.DataDir)
	if err != nil || len(afterIDs) != len(ids) {
		t.Fatal("disabled private report stored", err)
	}
	for range 3 {
		post("news", key, ">>1 !report disabled vote")
	}
	if voteCount(owner) != 0 || denialCount(owner) != 0 {
		t.Fatal("disabled public reports counted")
	}
	for range 3 {
		post("other", otherKey, ">>1 !report other board vote")
	}
	if denialCount(other.ID) != 1 {
		t.Fatal("other board affected")
	}
	restart()
	if repo.posting[owner].autoReports.Load().Enabled || voteCount(owner) != 0 || denialCount(owner) != 0 {
		t.Fatal("disabled state lost on restart")
	}
	save(&on)
	post("news", key, ">>1 !report new vote")
	if voteCount(owner) != 1 || denialCount(owner) != 0 {
		t.Fatal("pre-enable votes restored")
	}
	restart()
	if voteCount(owner) != 1 || denialCount(owner) != 0 {
		t.Fatal("new vote recovery")
	}
	post("report", "1", reference)
	post("news", key, ">>1 !report final vote")
	if denialCount(owner) != 1 {
		t.Fatal("new public/private quorum")
	}
	save(&off)
	if denialCount(owner) != 1 || denialCount(other.ID) != 1 {
		t.Fatal("existing stops removed")
	}
	restart()
	if denialCount(owner) != 1 {
		t.Fatal("existing stop lost on restart")
	}
	var persisted siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &persisted); err != nil || persisted.MinimumReader < 84 {
		t.Fatal("reader protection", err)
	}
}

func TestBoardAutoReportsStrictJSONAndForm(t *testing.T) {
	initial := boardValue{Settings: defaultBoardSettings()}
	raw, _ := json.Marshal(initial.Settings.Posting)
	var posting boardPosting
	if err := strictjson.Decode(raw, &posting); err != nil || !boardAutoReportsEnabled(posting.AutoReports) {
		t.Fatal("legacy default", err)
	}
	for _, bad := range []string{
		`"auto_reports":{"enabled":false,"since_ns":"1","extra":true}`,
		`"auto_reports":{"enabled":false}`,
		`"auto_reports":{"enabled":false,"enabled":true,"since_ns":"1"}`,
		`"auto_reports":{"enabled":"false","since_ns":"1"}`,
		`"auto_reports":{"enabled":null,"since_ns":"1"}`,
		`"auto_reports":true`,
	} {
		value := strings.TrimSuffix(string(raw), "}") + "," + bad + "}"
		if strictjson.Decode([]byte(value), &posting) == nil {
			t.Fatal("invalid persisted JSON accepted", bad)
		}
	}
	for _, on := range []bool{true, false} {
		input := boardEdit(initial)
		input.AutoReportsEnabled = &on
		form := adminBoardFields(input)
		decoded, err := parseAdminBoardFields(form)
		if err != nil || decoded.AutoReportsEnabled == nil || *decoded.AutoReportsEnabled != on {
			t.Fatal("form toggle", err)
		}
		form.Set("auto_reports_enabled", "garbage")
		if _, err := parseAdminBoardFields(form); err == nil {
			t.Fatal("invalid boolean accepted")
		}
	}
	old := &boardAutoReportSettings{Enabled: false, Since: 2}
	if validateBoardAutoReports(old, &boardAutoReportSettings{Enabled: true, Since: 1}) == nil || validateBoardAutoReports(old, nil) == nil {
		t.Fatal("cutoff rollback accepted")
	}
}

func TestBoardAutoReportsScope(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	assigned, err := repo.CreateBoard(t.Context(), "assigned", "担当板")
	if err != nil {
		t.Fatal(err)
	}
	outside, err := repo.CreateBoard(t.Context(), "outside", "担当外")
	if err != nil {
		t.Fatal(err)
	}
	accounts := make(map[string]AdministratorInfo)
	for _, role := range []string{"board_admin", "moderator"} {
		account, err := repo.CreateAdministrator("report."+role, "通報設定", adminTestSecret, AdministratorAccess{Role: role, Boards: []domain.ID{assigned.ID}, Permissions: []string{}, Enabled: true})
		if err != nil {
			t.Fatal(err)
		}
		accounts[role] = account
		repo.Close()
		repo, err = OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			t.Fatal(err)
		}
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer client.server.Close()
	for _, role := range []string{"board_admin", "moderator"} {
		account := accounts[role]
		cookie, session, err := repo.adminAuth.Create(account.ID, account.Generation, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		client.cookies["oimo_admin"] = &http.Cookie{Name: "oimo_admin", Value: cookie}
		for _, board := range []BoardInfo{assigned, outside} {
			path := "/api/v1/boards/" + board.ID.String() + "/settings"
			edit := boardEdit(boardValue{Settings: defaultBoardSettings()})
			off := false
			edit.AutoReportsEnabled = &off
			raw, _ := json.Marshal(edit)
			headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {session.CSRF(path)}, "If-Match": {`"ignored"`}, "Idempotency-Key": {domain.NewID().String()}}
			expected := 403
			if role == "board_admin" && board.ID == assigned.ID {
				res, row := client.board(board.ID.String())
				headers.Set("If-Match", res.Header.Get("ETag"))
				row.Settings.AutoReportsEnabled = &off
				raw, _ = json.Marshal(row.Settings)
				expected = 200
			}
			res, body := client.request("PATCH", path, string(raw), headers)
			if res.StatusCode != expected {
				t.Fatal(role, board.Key, res.StatusCode, body)
			}
		}
	}
	if repo.posting[outside.ID].autoReports.Load() != nil {
		t.Fatal("outside board changed")
	}
}
