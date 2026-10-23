// 検索条件、公開送信の失効、HTML削除確認と再送を実際の保存経路で検査する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func TestTitleQueryContract(t *testing.T) {
	for _, raw := range []string{"q=a&q=b", "page=0", "page=101", "page=01", "state=hidden", "other=x", "q=" + strings.Repeat("あ", 129), "q=a+b+c+d+e+f+g+h+i", "from=2026-10-03T00:00:00Z&until=2026-10-03T00:00:00Z"} {
		v, _ := url.ParseQuery(raw)
		if _, e := parseTitleQuery(v); e == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	v := url.Values{"q": {"ABC abc 日本"}, "from": {"2026-10-03T00:00:00Z"}, "until": {"2026-10-04T00:00:00Z"}, "state": {"active"}}
	q, e := parseTitleQuery(v)
	if e != nil || len(q.Terms) != 2 {
		t.Fatal(q, e)
	}
	s := &app.ThreadSummary{Title: "Abc 日本語", State: "active", Created: domain.Time(time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC).UnixNano())}
	if !q.matches(s) {
		t.Fatal("AND/start boundary")
	}
	s.Created = domain.Time(q.Until.UnixNano())
	if q.matches(s) {
		t.Fatal("end must be exclusive")
	}
	if asciiFold("ÄＡABC") != "ÄＡabc" {
		t.Fatal("non ASCII folding")
	}
}
func TestSearchAndModerationHTML(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	info, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	form := formServer(t, repo, siteID(repo.site.State()), info.ID)
	defer form.Close()
	accepted, e := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"ABC 日本 <script>"}, "MESSAGE": {"not-a-searchable-body"}, "oimo_request_id": {"search-create-0001"}})
	if e != nil || !accepted.Accepted {
		t.Fatal(accepted, e)
	}
	_, boards, e := repo.webBoards()
	if e != nil {
		t.Fatal(e)
	}
	q, _ := parseTitleQuery(url.Values{"q": {"abc 日本"}})
	rows, more, e := searchTitlesForTest(repo, context.Background(), q, boards)
	if e != nil || len(rows) != 1 || more {
		t.Fatal(rows, more, e)
	}
	request := func(path, method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, cfg.Public.BaseURL+path, nil)
		w := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(w, req)
		return w
	}
	w := request("/search?q=abc+日本", "GET")
	if w.Code != 200 || !strings.Contains(w.Body.String(), fmt.Sprintf("/news/%d/", accepted.Key)) || strings.Contains(w.Body.String(), "not-a-searchable-body") || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal(w.Code, w.Body.String())
	}
	head := request("/search?q=abc+日本", "HEAD")
	// 日時ショートカットの現在時刻は要求ごとに変わるため、別要求の表現長とは比較しない。
	headLength, err := strconv.Atoi(head.Header().Get("Content-Length"))
	if head.Code != 200 || head.Body.Len() != 0 || err != nil || headLength <= 0 || w.Header().Get("Content-Length") != strconv.Itoa(w.Body.Len()) {
		t.Fatal("HEAD mismatch")
	}
	if request("/search?board=absent", "GET").Code != 404 || request("/search?q=x&q=y", "GET").Code != 400 {
		t.Fatal("query validation")
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	listPath := fmt.Sprintf("/boards/%s/threads", info.ID)
	res, body := client.request("GET", listPath+"?page=1", "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, fmt.Sprint(accepted.Key)) {
		t.Fatal(res.StatusCode, body)
	}
	res, _ = client.request("GET", listPath+"?page=2", "", nil)
	if res.StatusCode != 404 {
		t.Fatal("out of range page", res.StatusCode)
	}
	res, _ = client.request("GET", listPath+"?other=1", "", nil)
	if res.StatusCode != 400 {
		t.Fatal("unknown list condition", res.StatusCode)
	}
	path := fmt.Sprintf("/boards/%s/threads/%d/moderation", info.ID, accepted.Key)
	res, body = client.request("GET", path, "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	fields := pageFields(body)
	fields.Set("kind", "redact")
	fields.Set("ranges", "1")
	fields.Set("mode", "aboon")
	fields.Set("hide_title", "true")
	fields.Set("step", "confirm")
	headers := http.Header{"Content-Type": {"application/x-www-form-urlencoded"}}
	res, body = client.request("POST", path, fields.Encode(), headers)
	if res.StatusCode != 200 || !strings.Contains(body, "削除内容の確認") || !strings.Contains(body, "この対象へ適用") {
		t.Fatal(res.StatusCode, body)
	}
	snapshot, _ := repo.Thread(context.Background(), info.ID, accepted.Key)
	if snapshot.Revision != 1 {
		t.Fatal("confirmation mutated thread")
	}
	confirmed := pageFields(body)
	confirmed.Set("step", "apply")
	res, body = client.request("POST", path, confirmed.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal(res.StatusCode, body)
	}
	// 旧検索候補は取得済みでも送信リースを再取得できない。
	if lease, e := rows[0].publication.AcquirePublic(domain.Time(time.Now().UnixNano()), nil); e == nil {
		lease.Close()
		t.Fatal("stale search title lease")
	}
	rows, _, e = searchTitlesForTest(repo, context.Background(), q, boards)
	if e != nil || len(rows) != 0 {
		t.Fatal("deleted title still searchable", rows, e)
	}
	res, body = client.request("POST", path, confirmed.Encode(), headers)
	if res.StatusCode != 303 {
		t.Fatal("same operation retry", res.StatusCode, body)
	}
	res, body = client.request("GET", path, "", nil)
	if res.StatusCode != 200 || !strings.Contains(body, "<dt>保存掃除</dt><dd>未完了</dd>") || !strings.Contains(body, "<dt>公開反映</dt><dd>公開へ反映済み</dd>") {
		t.Fatal(res.StatusCode, body)
	}
	form.Close()
	client.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	_, boards, _ = repo.webBoards()
	rows, _, e = searchTitlesForTest(repo, context.Background(), q, boards)
	if e != nil || len(rows) != 0 {
		t.Fatal("rebuild exposed deleted title", rows, e)
	}
}
func TestModerationFieldValidation(t *testing.T) {
	base := func(raw string) url.Values {
		return url.Values{"kind": {"redact"}, "ranges": {raw}, "mode": {"aboon"}, "hide_title": {"false"}}
	}
	for _, raw := range []string{"", "0", "01", "2-1", "1,1", "3,2", "1-257", "1-2-3", "1,<script>"} {
		if _, e := parseModerationFields(base(raw)); e == nil {
			t.Fatal("accepted", raw)
		}
	}
	if edit, e := parseModerationFields(base("1,3-5")); e != nil || len(edit.Ranges) != 2 {
		t.Fatal(edit, e)
	}
}

// TestSearchBusyBoard は列の長時間IOへ検索が並ばず、資源を解放して再試行できることを確認する。
func TestSearchBusyBoard(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	info, e := repo.CreateBoard(context.Background(), "busysearch", "検索混雑")
	if e != nil {
		t.Fatal(e)
	}
	_, boards, _ := repo.webBoards()
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		_, e := repo.posting[info.ID].worker.Submit(context.Background(), func() (any, error) { close(started); <-release; return nil, nil })
		done <- e
	}()
	<-started
	q, _ := parseTitleQuery(url.Values{})
	_, _, e = searchTitlesForTest(repo, context.Background(), q, boards)
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !errors.Is(e, board.ErrBusy) {
		t.Fatal("search queued behind IO", e)
	}
	if len(repo.searchWorkers) != 0 || len(repo.searchRequests) != 0 {
		t.Fatal("search admission leaked")
	}
	if _, _, e = searchTitlesForTest(repo, context.Background(), q, boards); e != nil {
		t.Fatal("search retry", e)
	}
}

func TestSearchAdmissionCancellation(t *testing.T) {
	repo := &Repository{}
	repo.searchOnce.Do(func() { repo.searchWorkers = make(chan struct{}, 4); repo.searchRequests = make(chan struct{}, 68) })
	for i := 0; i < 4; i++ {
		repo.searchWorkers <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := searchTitlesForTest(repo, ctx, titleQuery{Page: 1}, nil); !errors.Is(e, context.Canceled) {
		t.Fatal("cancelled search waited", e)
	}
	if len(repo.searchRequests) != 0 || len(repo.searchWorkers) != 4 {
		t.Fatal("cancelled search changed another reservation")
	}
	for i := 0; i < 4; i++ {
		<-repo.searchWorkers
	}
	for i := 0; i < 68; i++ {
		repo.searchRequests <- struct{}{}
	}
	if _, _, e := searchTitlesForTest(repo, context.Background(), titleQuery{Page: 1}, nil); e == nil {
		t.Fatal("queue capacity ignored")
	}
	if len(repo.searchRequests) != 68 {
		t.Fatal("capacity rejection changed reservations")
	}
	for i := 0; i < 68; i++ {
		<-repo.searchRequests
	}
	if _, _, e := searchTitlesForTest(repo, context.Background(), titleQuery{Page: 1}, nil); e != nil {
		t.Fatal("capacity not reusable", e)
	}
}

// searchTitlesForTest は候補を複製して送信枠を解放する。業務経路は送信完了まで保持する。
func searchTitlesForTest(repo *Repository, ctx context.Context, q titleQuery, boards []publicBoard) ([]titleRow, bool, error) {
	result, err := repo.searchTitles(ctx, q, boards)
	if err != nil {
		return nil, false, err
	}
	defer result.Close()
	return append([]titleRow{}, result.Rows...), result.More, nil
}
