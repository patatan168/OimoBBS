// 監査画面の操作者選択で、ページや操作種別に依存せず担当範囲を守ることを確認する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditActorOptionsScopeAndSelection(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	b, err := repo.CreateBoard(t.Context(), "audit", "記録用の板")
	if err != nil {
		t.Fatal(err)
	}
	limited, err := repo.CreateAdministrator("audit-reader", "記録の担当者", adminTestSecret, AdministratorAccess{Role: "board_admin", Boards: []domain.ID{b.ID}, Permissions: []string{}, Enabled: true})
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
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	_, page, _ := c.audit("")
	s, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	admin, capID, outside, old, missing := domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID(), domain.NewID()
	otherBoard := domain.NewID()
	now := time.Now()
	page.From, page.To = now.Add(-time.Hour).Format(time.RFC3339Nano), now.Add(time.Hour).Format(time.RFC3339Nano)
	page.Board, page.Actor, page.Action = b.ID.String(), admin.String(), "rule_create"
	entries := []auditIndexedEntry{
		{entry: AuditEntry{Owner: b.ID, Board: &b.ID, ActorID: &admin, ActorKind: "administrator", Action: "rule_create"}, at: now},
		{entry: AuditEntry{Owner: b.ID, Board: &b.ID, ActorID: &capID, ActorKind: "cap", Action: "cap_command_delete"}, at: now},
		{entry: AuditEntry{Owner: b.ID, Board: &b.ID, ActorID: &capID, ActorKind: "cap", Action: "cap_command_delete_applied"}, at: now},
		{entry: AuditEntry{Owner: otherBoard, Board: &otherBoard, ActorID: &outside}, at: now},
		{entry: AuditEntry{Owner: b.ID, ActorID: &old}, at: now.Add(-2 * time.Hour)},
	}
	repo.mu.Lock()
	repo.auditIndex.days = map[string][]auditIndexedEntry{now.Format("20060102"): entries}
	repo.mu.Unlock()
	options, err := repo.auditActorOptions(s, page)
	if err != nil || len(options) != 2 {
		t.Fatal("scope, period or deduplication", options, err)
	}
	labels := map[string]string{}
	for _, option := range options {
		labels[option.Code] = option.Label
	}
	if labels[admin.String()] != "管理者："+admin.String() || labels[capID.String()] != "CAP："+capID.String() {
		t.Fatal("actor kinds", options)
	}
	_, limitedSession, err := repo.adminAuth.Create(limited.ID, limited.Generation, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := repo.auditActorOptions(limitedSession, page); err != nil || len(got) != 2 {
		t.Fatal("board administrator choices", got, err)
	}
	deniedPage := page
	deniedPage.Board = otherBoard.String()
	if _, err := repo.auditActorOptions(limitedSession, deniedPage); err == nil {
		t.Fatal("outside board choices accepted")
	}
	deniedPage.Board = ""
	if _, err := repo.auditActorOptions(limitedSession, deniedPage); err == nil {
		t.Fatal("site choices accepted for board administrator")
	}
	page.Actor = missing.String()
	options, err = repo.auditActorOptions(s, page)
	if err != nil || len(options) != 3 {
		t.Fatal("missing selection lost", options, err)
	}
	// 現在の管理者名は本人、または再認証済みsite_adminだけが参照できる。
	repo.mu.Lock()
	day := now.Format("20060102")
	repo.auditIndex.days[day] = append(repo.auditIndex.days[day],
		auditIndexedEntry{entry: AuditEntry{Owner: b.ID, Board: &b.ID, ActorID: &s.Admin, ActorKind: "admin"}, at: now},
		auditIndexedEntry{entry: AuditEntry{Owner: b.ID, Board: &b.ID, ActorID: &limited.ID, ActorKind: "admin"}, at: now})
	repo.mu.Unlock()
	labelFor := func(session adminauth.Session, id domain.ID) string {
		t.Helper()
		options, err := repo.auditActorOptions(session, page)
		if err != nil {
			t.Fatal(err)
		}
		for _, option := range options {
			if option.Code == id.String() {
				return option.Label
			}
		}
		t.Fatal("missing actor")
		return ""
	}
	if labelFor(s, limited.ID) != "管理者："+limited.ID.String() || labelFor(limitedSession, s.Admin) != "管理者："+s.Admin.String() {
		t.Fatal("other administrator names escaped role/reauth scope")
	}
	if !strings.Contains(labelFor(limitedSession, limited.ID), "記録の担当者") {
		t.Fatal("own name missing")
	}
	raw, fresh, err := repo.adminAuth.MarkReauthenticated(c.cookies["oimo_admin"].Value, s, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c.cookies["oimo_admin"].Value = raw
	s = fresh
	if !strings.Contains(labelFor(s, limited.ID), "記録の担当者") {
		t.Fatal("reauthenticated site administrator cannot identify actor")
	}
	// 失効したセッションには選択肢も返さない。
	repo.mu.Lock()
	repo.adminAuth.Delete(c.cookies["oimo_admin"].Value)
	repo.mu.Unlock()
	if _, err = repo.auditActorOptions(s, page); err == nil {
		t.Fatal("revoked session accepted")
	}
}

func TestAdminAuditSelectHTML(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	selected := domain.NewID().String()
	res, body := c.request("GET", "/audit?"+url.Values{"actor": {selected}}.Encode(), "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, `<select name="actor"`) || !strings.Contains(body, `value="`+selected+`" selected`) || strings.Contains(body, `<input name="actor"`) || !strings.Contains(body, "該当する管理操作はありません") {
		t.Fatal("actor select or empty state", res.StatusCode, body)
	}
	if auditTimeLabel("2026-10-18T23:15:05Z") != "2026/10/19 08:15:05" {
		t.Fatal("JST date")
	}
}

// TestAdminAuditBrowser は隔離サーバーの管理パスから実フォームと狭幅表示を確認する。
func TestAdminAuditBrowser(t *testing.T) {
	node := os.Getenv("OIMO_BROWSER_NODE")
	if node == "" {
		t.Skip("OIMO_BROWSER_NODE/OIMO_PLAYWRIGHT/OIMO_CHROMIUMでブラウザ検証を有効化")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	if _, err := repo.CreateBoard(t.Context(), "audit", "記録用の板"); err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	// 旧要約では「その他」となる実ログからも操作を表示・検索できる。
	session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request, keyID := domain.Hash{1}, uint32(1)
	state := repo.site.State()
	frame, err := controlFrame(state, domain.NewID(), domain.Time(time.Now().UnixNano()), "board_categories_update",
		[]store.Mutation{{Collection: "site", Key: "state", Value: state.Rows["site:state"].Value}}, []string{},
		domain.Actor{Kind: "admin", ID: &session.Admin, Reason: "board_categories_update", Request: &request, Idempotency: &request, KeyID: &keyID})
	if err != nil {
		t.Fatal(err)
	}
	if result := repo.site.Append(frame); result.Status != store.Durable {
		t.Fatal(result)
	}
	for _, name := range []string{"監査画面の試験1", "監査画面の試験2"} {
		res, _ := c.site()
		headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {domain.NewID().String()}}
		res, body := c.request("PATCH", "/api/v1/site", `{"name":"`+name+`"}`, headers)
		if res.StatusCode != 200 {
			t.Fatal("fixture change", res.StatusCode, body)
		}
	}
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
	script, err := filepath.Abs("../../scripts/test-admin-audit-browser.mjs")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), node, script)
	command.Env = append(os.Environ(), "OIMO_AUDIT_URL="+origin+"/admin", "OIMO_TEST_PASSWORD="+adminTestSecret)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("browser: %v\n%s", err, output)
	}
	t.Log(string(output))
}

// TestAuditPresentationCoverage は既知の操作と項目を、意味不明なコードや「その他」へ落とさない。
func TestAuditPresentationCoverage(t *testing.T) {
	for action, fields := range auditActions {
		if auditLabels[action] == "" {
			t.Errorf("missing action label: %s", action)
		}
		for _, field := range fields {
			if auditFieldLabels[field] == "" {
				t.Errorf("missing field label: %s", field)
			}
		}
	}
	board := domain.NewID()
	row := newAuditRow(AuditEntry{Action: "network_fetch_failed", Fields: auditActions["network_fetch_failed"]}, nil)
	if row.Label != "回線分類データの取得に失敗" || !strings.Contains(row.Description, "前回成功") {
		t.Fatal(row)
	}
	capRow := newAuditRow(AuditEntry{Action: "cap_command_ban", Board: &board, Command: &CapCommandAudit{Thread: 123, Post: 45, Phase: "開始", Duration: "30m"}}, nil)
	if !strings.Contains(capRow.Description, "スレッド 123・レス 45") || capRow.PhaseLabel != "開始（完了未確認）" || capRow.DurationLabel != "30分" {
		t.Fatal(capRow)
	}
}
