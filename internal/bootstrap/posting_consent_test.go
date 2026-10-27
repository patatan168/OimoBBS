// 規約の編集・JST変更日・再同意と、専ブラ/Webの同意共有を実HTTPで検証する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"os"
	"strings"
	"testing"
	"time"
)

func consentAPI(t *testing.T, c *adminClient) (*http.Response, AdminConsent) {
	t.Helper()
	res, body := c.request("GET", "/api/v1/terms", "", nil)
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	var reply struct {
		Data AdminConsent `json:"data"`
	}
	if e := json.Unmarshal([]byte(body), &reply); e != nil {
		t.Fatal(e)
	}
	return res, reply.Data
}

func TestPostingConsentOnceAndTermsRevision(t *testing.T) {
	cfg, repo, board := anonymousAdminFixture(t, "required")
	defer func() { repo.Close() }()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	server, request, cookies := anonymousHTTP(t, repo, siteID(repo.site.State()))
	defer server.Close()
	fields := url.Values{"bbs": {"news"}, "subject": {"同意試験"}, "MESSAGE": {"一件目"}}
	res, body := request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || !strings.Contains(body, "2ch_X:cookie") || cookies["oimo_confirm"] == nil {
		t.Fatal("initial consent", res.StatusCode, body)
	}
	if len(repo.posting[board].threads) != 0 {
		t.Fatal("posted before consent")
	}
	decoded, err := textcodec.Decode([]byte(body))
	if err != nil || !strings.Contains(decoded, "【適用・準拠法】<br>\n本掲示板") || !strings.Contains(decoded, "利用してください。<br>\n<br>\n【禁止事項】") {
		t.Fatal("legacy consent line breaks", err, decoded)
	}
	if output := os.Getenv("OIMO_LEGACY_CONSENT_PAGE_OUTPUT"); output != "" {
		if err := os.WriteFile(output, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldCookie := *cookies["oimo_confirm"]
	request("POST", "/test/bbs.cgi", fields)
	var key uint64
	for k := range repo.posting[board].threads {
		key = k
	}
	if key == 0 {
		t.Fatal("consent resend did not post")
	}
	_, page := request("GET", fmt.Sprintf("/web/post?bbs=news&key=%d", key), nil)
	web := pageFields(page)
	web.Set("MESSAGE", "Webも確認は一回だけ")
	res, body = request("POST", "/web/post?bbs=news", web)
	if res.StatusCode != 303 {
		t.Fatal("Web repeated consent", res.StatusCode, body)
	}
	// 変更前のWebフォームも、規約更新後の投稿時に新規約を表示する。
	_, page = request("GET", fmt.Sprintf("/web/post?bbs=news&key=%d", key), nil)
	staleWeb := pageFields(page)
	staleWeb.Set("MESSAGE", "改訂前フォーム")
	before, v := consentAPI(t, c)
	text := v.Consent.text()
	text.TermsText += "\n改訂した利用規約 <script>unsafe()</script>"
	raw, _ := json.Marshal(text)
	headers := http.Header{"Content-Type": {"application/json"}, "If-Match": {before.Header.Get("ETag")}, "X-CSRF-Token": {before.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"terms-change-request-001"}}
	noCSRF := headers.Clone()
	delete(noCSRF, "X-CSRF-Token")
	res, _ = c.request("PATCH", "/api/v1/terms", string(raw), noCSRF)
	if res.StatusCode != 403 {
		t.Fatal("csrf", res.StatusCode)
	}
	started := time.Now()
	res, body = c.request("PATCH", "/api/v1/terms", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("save", res.StatusCode, body)
	}
	_, changed := consentAPI(t, c)
	if changed.Terms != v.Terms+1 || changed.Consent.Changed < domain.Time(started.UnixNano()) || changed.Consent.ChangedDate() != time.Now().In(time.FixedZone("JST", 9*3600)).Format("2006年01月02日") {
		t.Fatal("automatic revision/date", changed)
	}
	retry, rbody := c.request("PATCH", "/api/v1/terms", string(raw), headers)
	if retry.StatusCode != 200 || rbody != body {
		t.Fatal("idempotent replay", retry.StatusCode, rbody)
	}
	conflict := headers.Clone()
	conflict.Set("Idempotency-Key", "terms-stale-request-001")
	res, _ = c.request("PATCH", "/api/v1/terms", string(raw), conflict)
	if res.StatusCode != 412 {
		t.Fatal("CAS", res.StatusCode)
	}
	res, page = request("POST", "/web/post?bbs=news", staleWeb)
	if res.StatusCode != 200 || !strings.Contains(page, "改訂した利用規約 &lt;script&gt;") || strings.Contains(page, "<script>unsafe()") {
		t.Fatal("Web reconsent/escape", res.StatusCode, page)
	}
	snapshot, e := repo.Thread(t.Context(), board, key)
	if e != nil || snapshot.PostCount != 2 {
		t.Fatal("posted before revised consent", snapshot, e)
	}
	// 旧同意Cookieは専ブラから返しても無効。
	cookies["oimo_confirm"] = &oldCookie
	fields.Del("subject")
	fields.Set("key", fmt.Sprint(key))
	fields.Set("MESSAGE", "改訂後の専ブラ")
	res, body = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || !strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("legacy reconsent", res.StatusCode, body)
	}
	request("POST", "/test/bbs.cgi", fields)
	fields.Set("MESSAGE", "同意後の別本文")
	res, body = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("consent repeated", res.StatusCode, body)
	}
	// 同文保存は版・変更日時を維持する。別の管理操作や再送でもリセットしない。
	before, current := consentAPI(t, c)
	headers.Set("If-Match", before.Header.Get("ETag"))
	headers.Set("Idempotency-Key", "terms-no-change-001")
	res, body = c.request("PATCH", "/api/v1/terms", string(raw), headers)
	if res.StatusCode != 200 {
		t.Fatal("no change", res.StatusCode, body)
	}
	_, same := consentAPI(t, c)
	// ブラウザがtextareaをCRLFへ変換しても、同文として扱う。
	crlf := text
	crlf.TermsText = strings.ReplaceAll(text.TermsText, "\n", "\r\n")
	crlfRaw, _ := json.Marshal(crlf)
	headers.Set("Idempotency-Key", "terms-crlf-no-change-001")
	res, crlfBody := c.request("PATCH", "/api/v1/terms", string(crlfRaw), headers)
	if res.StatusCode != 200 {
		t.Fatal("CRLF", res.StatusCode, crlfBody)
	}
	_, normalized := consentAPI(t, c)
	if normalized != same {
		t.Fatal("line endings reset consent", normalized, same)
	}
	if same != current {
		t.Fatal("unchanged text reset consent", same, current)
	}
	_, html := c.request("GET", "/terms", "", nil)
	if output := os.Getenv("OIMO_CONSENT_PAGE_OUTPUT"); output != "" {
		if e := os.WriteFile(output, []byte(html), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if !strings.Contains(html, "textarea name=\"terms_text\"") || !strings.Contains(html, "JST") || strings.Contains(html, "<script>unsafe()") {
		t.Fatal("admin editor", html)
	}
	// 管理HTMLフォームでもCookie説明を変更でき、同意をリセットする。
	editFields := pageFields(html)
	editFields.Set("cookie_notice", same.Consent.CookieNotice+"\r\nCookie説明の改訂")
	editFields.Set("terms_text", strings.ReplaceAll(same.Consent.TermsText, "\n", "\r\n"))
	res, savePage := c.request("POST", "/terms", editFields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if res.StatusCode != 303 {
		t.Fatal("HTML save", res.StatusCode, savePage)
	}
	_, fromForm := consentAPI(t, c)
	if fromForm.Terms != same.Terms+1 || !strings.Contains(fromForm.Consent.CookieNotice, "\nCookie説明の改訂") || fromForm.Consent.Changed <= same.Consent.Changed {
		t.Fatal("HTML revision/date", fromForm)
	}
	same = fromForm
	res, body = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 || !strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("Cookie notice reconsent", res.StatusCode, body)
	}
	res, publicTerms := request("GET", "/web/terms", nil)
	if res.StatusCode != 200 || !strings.Contains(publicTerms, "改訂した利用規約 &lt;script&gt;") {
		t.Fatal("public terms", res.StatusCode, publicTerms)
	}
	server.Close()
	c.server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("reopen", e)
	}
	c = newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 {
		t.Fatal("relogin")
	}
	_, recovered := consentAPI(t, c)
	if recovered != same {
		t.Fatal("lost terms", recovered, same)
	}
}

func TestConsentChangedDateJST(t *testing.T) {
	p := PostingConsent{Changed: domain.Time(time.Date(2026, 10, 18, 15, 1, 0, 0, time.UTC).UnixNano())}
	if p.ChangedDate() != "2026年10月19日" {
		t.Fatal(p.ChangedDate())
	}
}

// 著作権の個別案内は無断転載禁止板に限り、共通規約はそれ以外の転載許可を示す。
func TestDefaultConsentReprintScope(t *testing.T) {
	text := defaultPostingConsent().TermsText
	if strings.Contains(text, "著作権は、投稿者に帰属") || !strings.Contains(text, "それ以外の板への投稿") || !strings.Contains(text, "転載・再配信を許可") {
		t.Fatal(text)
	}
	notices := reprintNotice()
	if len(notices) < 2 || !strings.Contains(notices[0].Text, "著作権は、投稿者に帰属") || !strings.Contains(notices[1].Text, "許諾") {
		t.Fatal(notices)
	}
}

// 初期規約には日本法・権利侵害の禁止と、削除/制限・法令に基づく開示の案内を含める。
func TestDefaultConsentJapaneseLawAndAbuse(t *testing.T) {
	text := defaultPostingConsent().TermsText
	for _, term := range []string{"日本法を適用", "日本の法令", "誹謗中傷", "侮辱", "脅迫", "無断掲載", "プライバシー", "著作権", "犯罪", "非表示・削除", "投稿制限", "削除依頼・照会", "法令に基づく手続"} {
		if !strings.Contains(text, term) {
			t.Fatal("default clause missing", term)
		}
	}
}
