// CAP専用スレッドのWeb作成・専ブラ返信・再送・再起動の権限境界を検証する。
package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"strings"
	"testing"
)

func TestCapOnlyThreadPostingAndRecovery(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "capthread", "CAPスレ試験")
	if err != nil {
		t.Fatal(err)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 || admin.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	creator, secret := createTestCap(t, repo, admin, board.ID, []string{"create", "post"})
	replier, replySecret := createTestCap(t, repo, admin, board.ID, []string{"post"})
	createOnly, createSecret := createTestCap(t, repo, admin, board.ID, []string{"create"})
	other, err := repo.CreateBoard(t.Context(), "othercap", "別板")
	if err != nil {
		t.Fatal(err)
	}
	foreign, foreignSecret := createTestCap(t, repo, admin, other.ID, []string{"post"})
	server := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer func() { server.Close() }()
	csrf, err := repo.IssueWebCSRF(t.Context(), board.ID, "web_create")
	if err != nil {
		t.Fatal(err)
	}
	fields := url.Values{"bbs": {"capthread"}, "subject": {"CAP告知"}, "MESSAGE": {"本文"}, "oimo_cap_only": {"1"}, "csrf": {csrf.Token}, "oimo_request_id": {"cap-thread-create-001"}, "mail": {"#cap:" + creator.ID.String() + ":" + secret}}
	cookies := []http.Cookie{*csrf.Cookie}
	pending, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if err != nil || pending.Confirmation == nil || !pending.Confirmation.CapOnly {
		t.Fatal("confirmation", pending, err)
	}
	preview := httptest.NewRecorder()
	writePostingPage(preview, 200, postingPage{Board: "capthread", Confirmation: pending.Confirmation, Fields: confirmationFields(map[string]string{"bbs": "capthread", "key": "", "oimo_cap_only": "1"})})
	if !strings.Contains(preview.Body.String(), `href="/web/post?bbs=capthread&amp;key=&amp;oimo_cap_only=1"`) {
		t.Fatal("confirmation edit link lost CAP restriction")
	}
	// 同意は公開条件へ束縛しないが、各投稿のCAP専用条件は入力から適用する。
	fields.Del("oimo_cap_only")
	fields.Set("oimo_request_id", "cap-thread-public-001")
	changed, err := sendWeb(server, fields, append(cookies, http.Cookie{Name: "oimo_confirm", Value: pending.Confirmation.Token}), cfg.Public.BaseURL)
	if err != nil || !changed.Accepted || changed.Confirmation != nil {
		t.Fatal("consent repeated for changed input", changed, err)
	}
	publicThread, err := repo.Thread(t.Context(), board.ID, changed.Key)
	if err != nil || publicThread.CapOnly {
		t.Fatal("public thread policy", err)
	}
	fields.Set("oimo_request_id", "cap-thread-create-001")
	fields.Set("oimo_cap_only", "1")
	cookies = append(cookies, http.Cookie{Name: "oimo_confirm", Value: pending.Confirmation.Token})
	created, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if err != nil || !created.Accepted {
		t.Fatal("web creation", created, err)
	}
	retry, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if err != nil || !retry.Duplicate || retry.Key != created.Key {
		t.Fatal("create retry", retry, err)
	}
	var site siteState
	if err := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != 71 {
		t.Fatal("reader boundary", site.MinimumReader, err)
	}
	snap, err := repo.Thread(t.Context(), board.ID, created.Key)
	if err != nil || snap == nil || !snap.CapOnly {
		t.Fatal("snapshot", err)
	}
	assertCapOnlyPages(t, repo, board.ID, created.Key)
	for _, path := range []string{"/boards", "/boards/" + board.ID.String() + "/settings"} {
		res, page := admin.request("GET", path, "", nil)
		want := repo.cfg.Public.BaseURL + "/web/post?bbs=capthread&amp;oimo_cap_only=1"
		if res.StatusCode != 200 || !strings.Contains(page, want) || !strings.Contains(page, "CAP専用スレッドを作成") {
			t.Fatal("admin CAP thread link", path, res.StatusCode)
		}
	}
	reply := url.Values{"bbs": {"capthread"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"返信"}, "oimo_request_id": {"cap-thread-reply-001"}}
	for _, mail := range []string{"", "#cap:" + createOnly.ID.String() + ":" + createSecret, "#cap:" + foreign.ID.String() + ":" + foreignSecret} {
		reply.Set("mail", mail)
		rejected, err := sendForm(server, reply)
		if err != nil || rejected.Accepted || rejected.Confirmation != nil {
			t.Fatal("unauthorized reply", rejected, err)
		}
	}
	reply.Set("mail", "#cap:"+replier.ID.String()+":"+replySecret)
	accepted, err := sendForm(server, reply)
	if err != nil || !accepted.Accepted || accepted.Number != 2 {
		t.Fatal("another cap reply", accepted, err)
	}
	// 通常スレッドは匿名作成・返信できる。
	plain := url.Values{"bbs": {"capthread"}, "subject": {"通常"}, "MESSAGE": {"本文"}, "oimo_request_id": {"cap-thread-plain-001"}}
	normal, err := sendForm(server, plain)
	if err != nil || !normal.Accepted {
		t.Fatal("ordinary create", normal, err)
	}
	plain.Del("subject")
	plain.Set("key", fmt.Sprint(normal.Key))
	plain.Set("oimo_request_id", "cap-thread-plain-reply")
	if normalReply, err := sendForm(server, plain); err != nil || !normalReply.Accepted {
		t.Fatal("ordinary reply", normalReply, err)
	}
	server.Close()
	admin.server.Close()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("recovery", err)
	}
	server = formServer(t, repo, siteID(repo.site.State()), board.ID)
	assertCapOnlyPages(t, repo, board.ID, created.Key)
	retry, err = sendForm(server, reply)
	if err != nil || !retry.Duplicate || retry.Number != 2 {
		t.Fatal("recovered retry", retry, err)
	}
	reply.Set("oimo_request_id", "cap-thread-reply-after")
	reply.Set("MESSAGE", "再起動後")
	reply.Del("mail")
	if rejected, err := sendForm(server, reply); err != nil || rejected.Accepted || rejected.Confirmation != nil {
		t.Fatal("recovered restriction", rejected, err)
	}
	reply.Set("mail", "#cap:"+replier.ID.String()+":"+replySecret)
	if accepted, err := sendForm(server, reply); err != nil || !accepted.Accepted || accepted.Number != 3 {
		t.Fatal("recovered cap reply", accepted, err)
	}
	// 匿名の制限付き作成も拒否する。
	plain.Del("key")
	plain.Set("subject", "不正作成")
	plain.Set("oimo_cap_only", "1")
	plain.Set("oimo_request_id", "cap-thread-invalid-001")
	if rejected, err := sendForm(server, plain); err != nil || rejected.Accepted || rejected.Confirmation != nil {
		t.Fatal("anonymous restricted create", rejected, err)
	}
}

// assertCapOnlyPages はフォーム・確認・閲覧の表示を検査し、制限の有無だけを利用者へ伝える。
func assertCapOnlyPages(t *testing.T, repo *Repository, board domain.ID, key uint64) {
	t.Helper()
	paths := []struct{ path, want string }{
		{"/web/post?bbs=capthread", `name="subject"`},
		{"/web/post?bbs=capthread&oimo_cap_only=1", `type="hidden" name="oimo_cap_only" value="1"`},
		{fmt.Sprintf("/web/post?bbs=capthread&key=%d", key), "この投稿は制限されています。"},
		{fmt.Sprintf("/test/read.cgi/capthread/%d/", key), "このスレッドへの返信は制限されています。"},
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:9080/web/post?bbs=capthread", nil)
	rec := httptest.NewRecorder()
	repo.renderEditing(rec, req, board, 422, "", "題", "本文", "入力内容を確認してください。", true)
	if rec.Code != 422 || pageFields(rec.Body.String()).Get("oimo_cap_only") != "1" {
		t.Fatal("lost restriction on validation error")
	}
	for _, p := range paths {
		req := httptest.NewRequest("GET", "http://127.0.0.1:9080"+p.path, nil)
		rec := httptest.NewRecorder()
		repo.BoardWebHandler(board, nil).ServeHTTP(rec, req.WithContext(context.Background()))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), p.want) {
			t.Fatal("page notice", p.path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "CAP専用（返信をCAPに限定）") || strings.Contains(rec.Body.String(), `type="checkbox" name="oimo_cap_only"`) {
			t.Fatal("CAP selector exposed", p.path)
		}
		assertNoPublicCapHelp(t, rec.Body.String())
		if p.path == "/web/post?bbs=capthread" && pageFields(rec.Body.String()).Has("oimo_cap_only") {
			t.Fatal("ordinary form gained CAP restriction")
		}
	}
	for _, path := range []string{
		"/web/post?bbs=capthread&oimo_cap_only=0",
		"/web/post?bbs=capthread&oimo_cap_only=",
		"/web/post?bbs=capthread&oimo_cap_only=1&oimo_cap_only=1",
		fmt.Sprintf("/web/post?bbs=capthread&key=%d&oimo_cap_only=1", key),
	} {
		req := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+path, nil)
		rec := httptest.NewRecorder()
		repo.BoardWebHandler(board, nil).ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatal("invalid CAP preset", path, rec.Code)
		}
	}
}
