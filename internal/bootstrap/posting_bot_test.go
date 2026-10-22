// Webの非表示欄を埋めるbotを保存前に拒否し、通常投稿と専ブラの互換性を検証する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/postcapture"
	"strconv"
	"strings"
	"testing"
)

func TestWebPostingHoneypot(t *testing.T) {
	cfg := testConfig(t)
	report, err := Initialize(cfg, "軽量bot対策")
	if err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "probe", "試験板")
	if err != nil {
		t.Fatal(err)
	}
	server := formServer(t, repo, report.SiteID, board.ID)
	defer server.Close()
	csrf, err := repo.IssueWebCSRF(t.Context(), board.ID, "web_create")
	if err != nil {
		t.Fatal(err)
	}
	fields := url.Values{"bbs": {"probe"}, "subject": {"通常投稿"}, "MESSAGE": {"正常な本文"}, "csrf": {csrf.Token}, "oimo_request_id": {"light-bot-web-create-0001"}}
	cookies := []http.Cookie{*csrf.Cookie}
	siteSeq := repo.site.State().Seq
	boardSeq := repo.posting[board.ID].control.State().Seq
	for _, trap := range []string{"https://spam.example", " ", "機械的な入力"} {
		fields.Set("oimo_contact", trap)
		result, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
		if err != nil || result.Accepted || result.Confirmation != nil {
			t.Fatal("trap passed", result, err)
		}
	}
	b := repo.posting[board.ID]
	if repo.site.State().Seq != siteSeq || b.control.State().Seq != boardSeq || len(b.threads) != 0 || len(b.journals) != 0 {
		t.Fatal("rejected bot mutated persistent posting state")
	}
	// 通常フォームの空欄は確認・受理へ進み、古いフォームの欄省略でも元結果を取得できる。
	fields.Set("oimo_contact", "")
	challenge, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if err != nil || challenge.Confirmation == nil {
		t.Fatal("normal confirmation", challenge, err)
	}
	cookies = append(cookies, http.Cookie{Name: "oimo_confirm", Value: challenge.Confirmation.Token})
	accepted, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if err != nil || !accepted.Accepted {
		t.Fatal("normal accepted", accepted, err)
	}
	fields.Del("oimo_contact")
	retried, err := sendWeb(server, fields, cookies, cfg.Public.BaseURL)
	if err != nil || !retried.Duplicate || retried.Key != accepted.Key {
		t.Fatal("old form retry", retried, err)
	}
	// 返信にも同じ入口の検査を適用する。
	replyCSRF, err := repo.IssueWebCSRF(t.Context(), board.ID, "web_reply")
	if err != nil {
		t.Fatal(err)
	}
	reply := url.Values{"bbs": {"probe"}, "key": {strconv.FormatUint(accepted.Key, 10)}, "MESSAGE": {"返信"}, "csrf": {replyCSRF.Token}, "oimo_request_id": {"light-bot-web-reply-0001"}, "oimo_contact": {"filled"}}
	rejected, err := sendWeb(server, reply, []http.Cookie{*replyCSRF.Cookie}, cfg.Public.BaseURL)
	if err != nil || rejected.Accepted || rejected.Confirmation != nil {
		t.Fatal("reply trap passed", rejected, err)
	}
	// 専ブラは未知の欄を従来どおり無視し、新たな必須欄を持たない。
	legacy, err := sendForm(server, url.Values{"bbs": {"probe"}, "subject": {"専ブラ"}, "MESSAGE": {"通常の専ブラ投稿"}, "oimo_request_id": {"light-bot-legacy-create-0001"}, "oimo_contact": {"legacy-unknown-value"}})
	if err != nil || !legacy.Accepted {
		t.Fatal("legacy compatibility", legacy, err)
	}
}

func TestPostingHoneypotForms(t *testing.T) {
	for _, page := range []postingPage{
		{Heading: "投稿", Board: "probe", CSRF: "csrf", RequestID: "request"},
		{Heading: "確認", Board: "probe", Confirmation: &ConfirmationChallenge{}, Fields: map[string]string{"bbs": "probe"}},
		{Heading: "再送", Board: "probe", Retry: true, Fields: map[string]string{"bbs": "probe"}},
	} {
		w := httptest.NewRecorder()
		writePostingPage(w, 200, page)
		body := w.Body.String()
		if w.Code != 200 || strings.Count(body, `name="oimo_contact"`) != 1 || !strings.Contains(body, `<p hidden>`) || !strings.Contains(body, `tabindex="-1" autocomplete="off"`) {
			t.Fatal("trap must be hidden, outside keyboard navigation and never duplicated")
		}
	}
}
