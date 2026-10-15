// Web CSRFを実Cookie/HTTP往復と永続投稿・再起動に接続して検証する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sendWeb(server *httptest.Server, fields url.Values, cookies []http.Cookie, origin string) (formResult, error) {
	req, e := http.NewRequest("POST", server.URL+"/web/post", strings.NewReader(fields.Encode()))
	if e != nil {
		return formResult{}, e
	}
	req.Host = "127.0.0.1:9080"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	for _, c := range cookies {
		req.AddCookie(&c)
	}
	response, e := server.Client().Do(req)
	if e != nil {
		return formResult{}, e
	}
	defer response.Body.Close()
	var result formResult
	e = json.NewDecoder(response.Body).Decode(&result)
	if result.Confirmation != nil {
		for _, c := range response.Cookies() {
			if c.Name == "oimo_confirm" {
				result.Confirmation.Token = c.Value
			}
		}
	}
	return result, e
}
func TestWebCSRFPostingAndRecovery(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "Web投稿試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { repo.Close() }()
	board, e := repo.CreateBoard(context.Background(), "news", "ニュース")
	if e != nil {
		t.Fatal(e)
	}
	server := formServer(t, repo, report.SiteID, board.ID)
	defer func() { server.Close() }()
	csrf, e := repo.IssueWebCSRF(context.Background(), board.ID, "web_create")
	if e != nil {
		t.Fatal(e)
	}
	if csrf.Cookie.Name != "oimo_web" || csrf.Cookie.Path != "/" || !csrf.Cookie.HttpOnly || csrf.Cookie.Secure || csrf.Cookie.Domain != "" || csrf.Cookie.SameSite != http.SameSiteLaxMode || csrf.Cookie.MaxAge != 3600 {
		t.Fatal("cookie attributes")
	}
	fields := url.Values{"bbs": {"news"}, "subject": {"Webの題"}, "MESSAGE": {"本文"}, "csrf": {csrf.Token}, "oimo_request_id": {"web-request-00001"}}
	for _, tc := range []struct {
		origin  string
		cookies []http.Cookie
		token   string
	}{
		{"", []http.Cookie{*csrf.Cookie}, csrf.Token},
		{"http://evil.test", []http.Cookie{*csrf.Cookie}, csrf.Token},
		{cfg.Public.BaseURL, nil, csrf.Token},
		{cfg.Public.BaseURL, []http.Cookie{*csrf.Cookie, *csrf.Cookie}, csrf.Token},
		{cfg.Public.BaseURL, []http.Cookie{*csrf.Cookie}, csrf.Token + "x"},
		{cfg.Public.BaseURL, []http.Cookie{*csrf.Cookie}, ""},
	} {
		fields.Set("csrf", tc.token)
		r, e := sendWeb(server, fields, tc.cookies, tc.origin)
		if e != nil || r.Accepted || r.Confirmation != nil {
			t.Fatal("CSRF bypass", r, e)
		}
	}
	b := repo.posting[board.ID]
	if len(b.threads) != 0 || len(b.journals) != 0 || b.control.State().Seq != 1 {
		t.Fatal("invalid CSRF persisted")
	}
	fields.Set("csrf", csrf.Token)
	challenge, e := sendWeb(server, fields, []http.Cookie{*csrf.Cookie}, cfg.Public.BaseURL)
	if e != nil || challenge.Accepted || challenge.Confirmation == nil {
		t.Fatal(challenge, e)
	}
	cookies := []http.Cookie{*csrf.Cookie, {Name: "oimo_confirm", Value: challenge.Confirmation.Token}}
	// 発行済みのCSRFと確認Cookieを、再起動後の永続用途鍵でも検証する。
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	server = formServer(t, repo, report.SiteID, board.ID)
	accepted, e := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if e != nil || !accepted.Accepted {
		t.Fatal(accepted, e)
	}
	retry, e := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if e != nil || !retry.Duplicate || retry.Key != accepted.Key {
		t.Fatal(retry, e)
	}
	fields.Set("key", fmt.Sprint(accepted.Key))
	fields.Del("subject")
	fields.Set("MESSAGE", "返信")
	wrongRoute, e := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if e != nil || wrongRoute.Accepted || wrongRoute.Confirmation != nil {
		t.Fatal("create CSRF used for reply", wrongRoute, e)
	}
	replyCSRF, e := repo.IssueWebCSRF(context.Background(), board.ID, "web_reply")
	if e != nil {
		t.Fatal(e)
	}
	fields.Set("csrf", replyCSRF.Token)
	fields.Set("oimo_request_id", "web-reply-0000001")
	challenge, e = sendWeb(server, fields, []http.Cookie{*replyCSRF.Cookie}, cfg.Public.BaseURL)
	if e != nil || challenge.Confirmation == nil {
		t.Fatal(challenge, e)
	}
	cookies = []http.Cookie{*replyCSRF.Cookie, {Name: "oimo_confirm", Value: challenge.Confirmation.Token}}
	reply, e := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if e != nil || !reply.Accepted || reply.Number != 2 {
		t.Fatal(reply, e)
	}
	snapshot, e := repo.Thread(context.Background(), board.ID, accepted.Key)
	if e != nil || snapshot == nil || snapshot.PostCount != 2 {
		t.Fatal(snapshot, e)
	}
	// Cookie秘密・フォーム署名を正本や署名記録へ混ぜない。
	e = filepath.WalkDir(cfg.DataDir, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		for _, secret := range []string{csrf.Cookie.Value, csrf.Token, replyCSRF.Cookie.Value, replyCSRF.Token} {
			if strings.Contains(string(raw), secret) {
				return fmt.Errorf("CSRF secret persisted in %s", path)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	b = repo.posting[board.ID]
	expired := replyCSRF.Cookie.Expires
	_, e = b.worker.Submit(context.Background(), func() (any, error) { b.clock = func() time.Time { return expired }; return nil, nil })
	if e != nil {
		t.Fatal(e)
	}
	rejected, e := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if e != nil || rejected.Accepted || rejected.Confirmation != nil {
		t.Fatal("expired CSRF reached confirmation/retry", rejected, e)
	}
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	restored, e := repo.Thread(context.Background(), board.ID, accepted.Key)
	if e != nil || restored == nil || string(restored.DAT) != string(snapshot.DAT) {
		t.Fatal("Web posts not recovered", e)
	}
}
