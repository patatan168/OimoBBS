// 実閲覧/受付前拒否の観測を管理HTTPから通常期限内で照会し、板scopeと選択列を守る。
package bootstrap

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"net/url"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAdminUnboundHTTPObservationQueryAndRestart(t *testing.T) {
	cfg, repo := adminFixture(t)
	board, e := repo.CreateBoard(t.Context(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.SetAdministratorAccess("owner", AdministratorAccess{Role: "site_admin", Boards: []domain.ID{}, Permissions: []string{"evidence.manage"}, Enabled: true}); e != nil {
		t.Fatal(e)
	}
	repo = reopenRejectedProduct(t, cfg, repo)
	public := optionalProductServer(t, repo)
	origin, e := url.Parse(cfg.Public.BaseURL)
	if e != nil {
		t.Fatal(e)
	}
	request := func(method, path string, fields url.Values) (*http.Response, error) {
		req, e := http.NewRequest(method, public.URL+path, strings.NewReader(fields.Encode()))
		if e != nil {
			return nil, e
		}
		req.Host = origin.Host
		if method == "POST" {
			req.Header.Set("Origin", cfg.Public.BaseURL)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return public.Client().Do(req)
	}
	response, e := request("GET", "/news/", nil)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	response, e = request("POST", "/web/post?bbs=news", url.Values{"MESSAGE": {"PRIVATE_INPUT_NEVER_COPY"}})
	if e != nil {
		t.Fatal(e)
	}
	if response.StatusCode < 400 {
		t.Fatal("invalid request accepted", response.StatusCode)
	}
	response.Body.Close()
	public.Close()
	if e = repo.optionalQueue.Close(t.Context()); e != nil {
		t.Fatal(e)
	}
	client := newAdminClient(t, repo)
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	list, _ := client.request("GET", "/api/v1/evidence/cases", "", nil)
	at := time.Now()
	input := evidenceInput{Number: "HTTP-1", Reason: "受付前拒否と閲覧の確認", Scope: disclosure.Scope{Board: board.ID, From: domain.Time(at.Add(-time.Hour).UnixNano()), To: domain.Time(at.UnixNano()), Records: []domain.ID{}}}
	res, c, body := evidencePost(t, client, "/api/v1/evidence/cases", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	query := "/api/v1/evidence/cases/" + c.ID.String() + "/http-query"
	res, c, body = evidencePost(t, client, query, evidenceInput{Reason: "結果確認"}, c.ETag(), tokens[query], domain.NewID().String())
	checkUnboundHTTPResult(t, res, body, false)
	client.server.Close()
	repo = reopenRejectedProduct(t, cfg, repo)
	defer repo.Close()
	client = newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login after restart")
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	res, c, body = evidencePost(t, client, query, evidenceInput{Reason: "接続確認", Columns: []string{"connection"}}, c.ETag(), tokens[query], domain.NewID().String())
	checkUnboundHTTPResult(t, res, body, true)
	assertMissingHTTPSelectionRejected(t, client, c.Scope)
	c = assertHTTPObservationHold(t, client, repo, c)
	client.server.Close()
	repo = reopenRejectedProduct(t, cfg, repo)
	defer repo.Close()
	client = newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login after hold restart")
	}
	assertHTTPObservationZIPAndRelease(t, client, cfg, c)
}

// checkUnboundHTTPResult は閲覧/拒否の結果と、選択外接続/秘密入力の非混入を確認する。
func checkUnboundHTTPResult(t *testing.T, res *http.Response, body string, connection bool) {
	t.Helper()
	if res.StatusCode != 200 || !strings.Contains(body, `"http_observation"`) || !strings.Contains(body, `"served"`) || !strings.Contains(body, `"rejected"`) {
		t.Fatal(res.StatusCode, body)
	}
	if strings.Contains(body, "PRIVATE_INPUT_NEVER_COPY") {
		t.Fatal("input leaked")
	}
	if strings.Contains(body, `"peer"`) != connection {
		t.Fatal("connection selection ignored", body)
	}
	for _, key := range []string{"written_bytes", "write_failed", "request_canceled", "finish_stage", "monotonic_elapsed_ns"} {
		if !strings.Contains(body, `"`+key+`"`) {
			t.Fatal("response observation omitted", key)
		}
	}
}

// assertMissingHTTPSelectionRejected は明示IDの欠落を空の成功照会に読み替えない。
func assertMissingHTTPSelectionRejected(t *testing.T, client *adminClient, scope disclosure.Scope) {
	t.Helper()
	scope.Records = []domain.ID{domain.NewID()}
	list, _ := client.request("GET", "/api/v1/evidence/cases", "", nil)
	input := evidenceInput{Number: "HTTP-MISSING", Reason: "固定ID照会", Scope: scope}
	res, c, body := evidencePost(t, client, "/api/v1/evidence/cases", input, list.Header.Get("ETag"), list.Header.Get("X-CSRF-Token"), domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	c, tokens := evidenceInfo(t, client, c.ID)
	route := "/api/v1/evidence/cases/" + c.ID.String() + "/http-query"
	res, _, body = evidencePost(t, client, route, evidenceInput{Reason: "接続確認", Columns: []string{"connection"}}, c.ETag(), tokens[route], domain.NewID().String())
	if res.StatusCode != 410 || strings.Contains(body, `"peer"`) {
		t.Fatal("missing selection accepted", res.StatusCode, body)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	hold := "/api/v1/evidence/cases/" + c.ID.String() + "/http-observation-hold"
	res, _, body = evidencePost(t, client, hold, evidenceInput{Reason: "固定ID保全"}, c.ETag(), tokens[hold], domain.NewID().String())
	if res.StatusCode != 410 {
		t.Fatal("missing hold accepted", res.StatusCode, body)
	}
	current, _ := evidenceInfo(t, client, c.ID)
	if current.HTTP != nil {
		t.Fatal("missing source produced hold intent")
	}
}

// assertHTTPObservationHold は管理操作で固定コピーを作り、元解除・期限後読出し・取消を検査する。
func assertHTTPObservationHold(t *testing.T, client *adminClient, repo *Repository, c disclosure.Case) disclosure.Case {
	t.Helper()
	c, tokens := evidenceInfo(t, client, c.ID)
	route := "/api/v1/evidence/cases/" + c.ID.String() + "/http-observation-hold"
	res, c, body := evidencePost(t, client, route, evidenceInput{Reason: "観測を保全"}, c.ETag(), tokens[route], domain.NewID().String())
	if res.StatusCode != 200 || c.HTTP == nil || !c.HTTP.Unbound || c.HTTP.State != "active" || c.HTTP.Reservation == nil || c.HTTP.Released == nil || c.State != "active" {
		t.Fatal("HTTP hold incomplete", res.StatusCode, body)
	}
	repo.mu.Lock()
	rows, e := repo.evidenceCases.HTTPRecords(c, time.Now().Add(8*24*time.Hour))
	repo.mu.Unlock()
	if e != nil || len(rows) < 2 {
		t.Fatal("held rows past original expiry", len(rows), e)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	query := "/api/v1/evidence/cases/" + c.ID.String() + "/http-query"
	res, c, body = evidencePost(t, client, query, evidenceInput{Reason: "保全結果", Columns: []string{"connection"}}, c.ETag(), tokens[query], domain.NewID().String())
	checkUnboundHTTPResult(t, res, body, true)
	if !strings.Contains(body, `"case_hold"`) {
		t.Fatal("ordinary retention used", body)
	}
	return c
}

// assertHTTPObservationZIPAndRelease は保全後の再起動から照会/署名ZIP/一回取得/解除へ接続する。
func assertHTTPObservationZIPAndRelease(t *testing.T, client *adminClient, cfg Config, c disclosure.Case) {
	t.Helper()
	c, tokens := evidenceInfo(t, client, c.ID)
	query := "/api/v1/evidence/cases/" + c.ID.String() + "/http-query"
	res, c, body := evidencePost(t, client, query, evidenceInput{Reason: "再起動後確認", Columns: []string{"connection"}}, c.ETag(), tokens[query], domain.NewID().String())
	checkUnboundHTTPResult(t, res, body, true)
	c, tokens = evidenceInfo(t, client, c.ID)
	extend := "/api/v1/evidence/cases/" + c.ID.String() + "/extend"
	wanted := c.Until + domain.Time(24*time.Hour)
	res, c, body = evidencePost(t, client, extend, evidenceInput{Reason: "保全延長", Until: wanted}, c.ETag(), tokens[extend], domain.NewID().String())
	if res.StatusCode != 200 || c.Until != wanted {
		t.Fatal("extend", res.StatusCode, body)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	exports := "/api/v1/evidence/cases/" + c.ID.String() + "/exports"
	res, c, body = evidencePost(t, client, exports, evidenceInput{Reason: "観測提出"}, c.ETag(), tokens[exports], domain.NewID().String())
	if res.StatusCode != 200 || len(c.Exports) != 1 || c.Exports[0].Kind != "http_observation" {
		t.Fatal("export", res.StatusCode, body)
	}
	v := c.Exports[0]
	assertHTTPObservationHTML(t, client)
	c, tokens = evidenceInfo(t, client, c.ID)
	download := "/api/v1/evidence/exports/" + v.ID.String() + "/download"
	res, _, body = evidencePost(t, client, download, evidenceInput{CaseID: c.ID, Reason: "取得"}, c.ETag(), tokens[download], domain.NewID().String())
	if res.StatusCode != 200 {
		t.Fatal("download", res.StatusCode, body)
	}
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), 32)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	defer clear(key)
	m, e := disclosure.VerifyZIP(bytes.NewReader([]byte(body)), int64(len(body)), key.Public().(ed25519.PublicKey))
	if e != nil || m.RecordKind != "http_observation" || m.Count < 2 || len(m.Columns) != 0 {
		t.Fatal("ZIP verify", m, e)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	res, _, body = evidencePost(t, client, download, evidenceInput{CaseID: c.ID, Reason: "再取得拒否"}, c.ETag(), tokens[download], domain.NewID().String())
	if res.StatusCode != 410 {
		t.Fatal("second download", res.StatusCode, body)
	}
	c, tokens = evidenceInfo(t, client, c.ID)
	release := "/api/v1/evidence/cases/" + c.ID.String() + "/release"
	res, c, body = evidencePost(t, client, release, evidenceInput{Reason: "保全解除"}, c.ETag(), tokens[release], domain.NewID().String())
	if res.StatusCode != 200 || c.State != "closed" || c.HTTP.State != "removed" {
		t.Fatal("release", res.StatusCode, body)
	}
}

// assertHTTPObservationHTML は固定HTTP案件の画面から本文/資格の選択肢が除外されることを検査する。
func assertHTTPObservationHTML(t *testing.T, client *adminClient) {
	t.Helper()
	res, html := client.request("GET", "/evidence", "", nil)
	if res.StatusCode != 200 {
		t.Fatal("evidence HTML", res.StatusCode, html)
	}
	start := strings.Index(html, "<h2>案件 HTTP-1</h2>")
	if start < 0 {
		t.Fatal("HTTP case absent")
	}
	card := html[start:]
	if end := strings.Index(card[1:], "<h2>案件 "); end >= 0 {
		card = card[:end+1]
	}
	if strings.Contains(card, `name="content"`) || strings.Contains(card, `name="principal"`) || !strings.Contains(card, "HTTP観測の提出物") {
		t.Fatal("HTTP case form has wrong columns", card)
	}
}
