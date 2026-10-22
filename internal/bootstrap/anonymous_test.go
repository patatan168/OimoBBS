// 匿名Cookieの実HTTP往復・追加枠・永続発行上限・失効と秘密非保存を検証する。
package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func anonymousFixture(t *testing.T, mode string, before ...func(*Repository, domain.ID, domain.ID)) (Config, *Repository, domain.ID, domain.ID) {
	t.Helper()
	cfg := testConfig(t)
	report, e := Initialize(cfg, "匿名試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	board, e := repo.CreateBoard(context.Background(), "news", "試験板")
	if e != nil {
		repo.Close()
		t.Fatal(e)
	}
	if _, e = repo.EnableAdmission(); e != nil {
		repo.Close()
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	for _, f := range before {
		f(repo, report.SiteID, board.ID)
	}
	if _, e = repo.EnableAnonymous(mode); e != nil {
		repo.Close()
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	return cfg, repo, report.SiteID, board.ID
}
func anonymousHTTP(t *testing.T, repo *Repository, site domain.ID) (*httptest.Server, feedRequest, map[string]*http.Cookie) {
	t.Helper()
	observer, e := evidence.NewHTTPObserver(site, domain.NewID(), "anonymous-test")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
	server.Config.ConnContext = observer.ConnContext
	server.Start()
	server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, fields url.Values, headers ...http.Header) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(fields.Encode()))
		req.Host = "127.0.0.1:9080"
		if len(headers) > 0 {
			req.Header = headers[0].Clone()
		}
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("Origin", repo.cfg.Public.BaseURL)
		}
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		body, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		for _, cookie := range res.Cookies() {
			if cookie.MaxAge < 0 {
				delete(cookies, cookie.Name)
			} else {
				cookies[cookie.Name] = cookie
			}
		}
		return res, string(body)
	}
	return server, request, cookies
}
func TestAnonymousHTTPAndRecovery(t *testing.T) {
	for _, mode := range []string{"required"} {
		t.Run(mode, func(t *testing.T) {
			cfg, repo, site, owner := anonymousFixture(t, mode)
			defer func() {
				if repo != nil {
					repo.Close()
				}
			}()
			policy := repo.anonymous.policy
			again, e := repo.EnableAnonymous(mode)
			if e != nil || !reflect.DeepEqual(again, policy) {
				t.Fatal("activation reset", e)
			}
			server, request, cookies := anonymousHTTP(t, repo, site)
			defer server.Close()
			fields := url.Values{"bbs": {"news"}, "subject": {"匿名投稿"}, "MESSAGE": {"検証本文"}, "oimo_request_id": {"anonymous-create-0001"}}
			res, page := request("POST", "/test/bbs.cgi", fields)
			first := cookies["oimo_anon"]
			if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") || first == nil || !first.HttpOnly || first.Path != "/" || first.Domain != "" || first.SameSite != http.SameSiteLaxMode {
				t.Fatal("anonymous confirmation", res.StatusCode)
			}
			token, e := repo.anonymous.verify(first.Value, time.Now())
			if e != nil {
				t.Fatal("token verification")
			}
			if mode == "required" {
				delete(cookies, "oimo_anon")
				res, page = request("POST", "/test/bbs.cgi", fields)
				rows, _ := repo.rateHistory()
				if res.StatusCode != 200 || !strings.Contains(page, "2ch_X:cookie") || len(rows) != 0 {
					t.Fatal("required accepted without return")
				}
				cookies["oimo_anon"] = first
			}
			res, page = request("POST", "/test/bbs.cgi", fields)
			if res.StatusCode != 200 || strings.Contains(page, "ERROR:") {
				t.Fatal("accepted", res.StatusCode, page)
			}
			rows, e := repo.rateHistory()
			if e != nil || len(rows) != 1 || len(rows[0].record.Keys) != 4 || rows[0].record.TokenStatus != "valid" || rows[0].record.Token == nil {
				t.Fatal("token acceptance proof", e)
			}
			broken := rows[0].record
			proof := *broken.Token
			proof.Rate.Subject[0] ^= 1
			broken.Token = &proof
			if repo.admission.validate(owner, broken) == nil {
				t.Fatal("token proof mutation accepted")
			}
			broken = rows[0].record
			broken.Keys = broken.Keys[:3]
			if repo.admission.validate(owner, broken) == nil {
				t.Fatal("missing token key accepted")
			}
			broken = rows[0].record
			broken.Schema = "form-post-v1"
			if repo.admission.validate(owner, broken) == nil {
				t.Fatal("old capture after token activation accepted")
			}
			subject := rows[0].record.Token.Subject
			if subject != repo.anonymous.subject(token.ID) {
				t.Fatal("token subject mismatch")
			}
			res, _ = request("POST", "/test/bbs.cgi", fields)
			if res.StatusCode != 200 {
				t.Fatal("receipt blocked")
			}
			server.Close()
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal("recovery", e)
			}
			// 回線が変わってIP枠に余裕があっても、同じCookieの作成枠を復元する。
			ip := netip.MustParseAddr("192.0.2.99")
			_, _, _, e = repo.admission.reserveAnonymous(owner, ip, true, time.Now, token.ID)
			var limited *abuse.RateLimited
			if !errors.As(e, &limited) {
				t.Fatal("token limit reset", e)
			}
			ticket, _, _, e := repo.admission.reserve(owner, ip, true, time.Now)
			if e != nil {
				t.Fatal("failed reservation consumed IP", e)
			}
			if e = repo.admission.limits.Release(ticket); e != nil {
				t.Fatal(e)
			}
			// Cookie署名値とID原文は、投稿・発行・失効の保存ファイルへ残さない。
			e = filepath.WalkDir(cfg.DataDir, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if entry.IsDir() {
					return nil
				}
				raw, e := os.ReadFile(path)
				if e != nil {
					return e
				}
				if bytes.Contains(raw, []byte(first.Value)) || bytes.Contains(raw, []byte(token.ID.String())) {
					return errors.New("reusable token material persisted")
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
			if e = repo.RevokeAnonymous(&subject); e != nil {
				t.Fatal(e)
			}
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = repo.anonymous.verify(first.Value, time.Now()); e == nil {
				t.Fatal("individual revocation lost")
			}
			replacement, e := repo.anonymousCookie("", ip, time.Now)
			if e != nil {
				t.Fatal(e)
			}
			if e = repo.RevokeAnonymous(nil); e != nil {
				t.Fatal(e)
			}
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			if _, e = repo.anonymous.verify(replacement.Value, time.Now()); e == nil {
				t.Fatal("generation revocation lost")
			}
		})
	}
}

func TestAnonymousIssuanceDurableAndRenewal(t *testing.T) {
	cfg, repo, _, _ := anonymousFixture(t, "required")
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	ip := netip.MustParseAddr("192.0.2.1")
	// 同時発行で上限を超えない。失敗要求からCookieを返さない。
	var mu sync.Mutex
	accepted := 0
	var wg sync.WaitGroup
	for range 55 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cookie, e := repo.anonymousCookie("", ip, time.Now)
			mu.Lock()
			defer mu.Unlock()
			if e == nil && cookie != nil {
				accepted++
			} else {
				var limited *abuse.RateLimited
				if cookie != nil || !errors.As(e, &limited) {
					t.Error("unexpected issue result", e)
				}
			}
		}()
	}
	wg.Wait()
	if accepted != 50 {
		t.Fatal("issue cap", accepted)
	}
	if e := repo.Close(); e != nil {
		t.Fatal(e)
	}
	var e error
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	cookie, e := repo.anonymousCookie("", ip, time.Now)
	var limited *abuse.RateLimited
	if cookie != nil || !errors.As(e, &limited) || limited.RetryAfter == 0 {
		t.Fatal("issue cap reset", e)
	}
	// 同IDの更新は新規発行枠を消費しない。期限だけを延ばす。
	now := time.Now()
	old := abuse.Anon{ID: domain.NewID(), Generation: 1, Issued: now.Add(-24 * 24 * time.Hour).Unix(), Expires: now.Add(6 * 24 * time.Hour).Unix()}
	signed, e := abuse.IssueAnon(old, repo.anonymous.key[:], 4)
	if e != nil {
		t.Fatal(e)
	}
	updated, e := repo.anonymousCookie(signed, ip, time.Now)
	if e != nil || updated == nil {
		t.Fatal("renewal", e)
	}
	renewed, e := repo.anonymous.verify(updated.Value, time.Now())
	if e != nil || renewed.ID != old.ID || renewed.Expires <= old.Expires {
		t.Fatal("renewed identity")
	}
	if _, e = repo.anonymousCookie(updated.Value, ip, time.Now); e != nil {
		t.Fatal("valid cookie attempted issuance", e)
	}
	if wait := tokenIssueWait(100, []domain.Time{100, 200, 300, 400, 500}, 5); wait != 0 {
		t.Fatal("expiry boundary")
	}
}

func TestAnonymousWebRejectsInvalidCookie(t *testing.T) {
	_, repo, site, _ := anonymousFixture(t, "required")
	defer repo.Close()
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer server.Close()
	_, page := request("GET", "/web/post?bbs=news", nil)
	fields := pageFields(page)
	fields.Set("subject", "Web匿名")
	fields.Set("MESSAGE", "秘密を公開しない")
	res, _ := request("POST", "/web/post?bbs=news", fields)
	if res.StatusCode != 200 || cookies["oimo_anon"] == nil {
		t.Fatal("web issue")
	}
	// 改変Cookieは投稿を受理せず、検証済みCookieの返送を要求する。
	cookies["oimo_anon"].Value = "invalid.signature"
	res, _ = request("POST", "/web/post?bbs=news", fields)
	if res.StatusCode != 200 {
		t.Fatal("invalid cookie confirmation", res.StatusCode)
	}
	rows, e := repo.rateHistory()
	if e != nil || len(rows) != 0 {
		t.Fatal("unverified token adopted", e)
	}
}

func TestAnonymousIssueFailureDoesNotExposeCookie(t *testing.T) {
	_, repo, _, _ := anonymousFixture(t, "required")
	defer repo.Close()
	if e := repo.site.Close(); e != nil {
		t.Fatal(e)
	}
	cookie, e := repo.anonymousCookie("", netip.MustParseAddr("192.0.2.1"), time.Now)
	if e == nil || cookie != nil || !repo.stopped {
		t.Fatal("cookie exposed before durable issue")
	}
}

func TestAnonymousIssueCapHTTPModes(t *testing.T) {
	for _, mode := range []string{"required"} {
		t.Run(mode, func(t *testing.T) {
			_, repo, site, _ := anonymousFixture(t, mode)
			defer repo.Close()
			server, request, cookies := anonymousHTTP(t, repo, site)
			defer server.Close()
			fields := url.Values{"bbs": {"news"}, "subject": {"発行枠"}, "MESSAGE": {"Cookieなし"}, "oimo_request_id": {"anonymous-issue-cap-001"}}
			// HTTP確認要求の頻度枠とは独立に、永続発行枠50件を消費する。
			for range 50 {
				if _, err := repo.anonymousCookie("", netip.MustParseAddr("127.0.0.1"), time.Now); err != nil {
					t.Fatal(err)
				}
			}
			delete(cookies, "oimo_anon")
			delete(cookies, "oimo_confirm")
			res, _ := request("POST", "/test/bbs.cgi", fields)
			if cookies["oimo_anon"] != nil {
				t.Fatal("issued above cap")
			}
			if mode == "required" {
				if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
					t.Fatal("required issuance cap", res.StatusCode)
				}
				rows, _ := repo.rateHistory()
				if len(rows) != 0 {
					t.Fatal("required accepted without token")
				}
			} else {
				if res.StatusCode != 200 {
					t.Fatal("optional confirmation failed", res.StatusCode)
				}
				res, _ = request("POST", "/test/bbs.cgi", fields)
				rows, _ := repo.rateHistory()
				if res.StatusCode != 429 || len(rows) != 0 || res.Header.Get("Retry-After") == "" {
					t.Fatal("discarded optional Cookie bypassed recast", res.StatusCode)
				}

			}
		})
	}
}

func TestAnonymousNetworkIssueCap(t *testing.T) {
	_, repo, _, _ := anonymousFixture(t, "required")
	defer repo.Close()
	for i := 0; i < 50; i++ {
		ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})
		if cookie, e := repo.anonymousCookie("", ip, time.Now); e != nil || cookie == nil {
			t.Fatal("network initial issue", i, e)
		}
	}
	cookie, e := repo.anonymousCookie("", netip.MustParseAddr("192.0.2.200"), time.Now)
	var limited *abuse.RateLimited
	if cookie != nil || !errors.As(e, &limited) {
		t.Fatal("network cap bypass", e)
	}
	if cookie, e = repo.anonymousCookie("", netip.MustParseAddr("192.0.3.1"), time.Now); e != nil || cookie == nil {
		t.Fatal("different network blocked", e)
	}
}

func TestAnonymousPreservesEarlierAdmission(t *testing.T) {
	var oldRows []boardRateRecord
	_, repo, _, _ := anonymousFixture(t, "required", func(repo *Repository, site, owner domain.ID) {
		server := formServer(t, repo, site, owner)
		defer server.Close()
		result, e := sendForm(server, url.Values{"bbs": {"news"}, "subject": {"Cookie導入前"}, "MESSAGE": {"旧投稿の保存"}})
		if e != nil || !result.Accepted {
			t.Fatal("pre-activation post", e)
		}
		oldRows, e = repo.rateHistory()
		if e != nil {
			t.Fatal(e)
		}
	})
	defer repo.Close()
	rows, e := repo.rateHistory()
	if e != nil || !reflect.DeepEqual(rows, oldRows) || len(rows) != 1 || rows[0].record.Schema != postcapture.Schema || len(rows[0].record.Keys) != 3 {
		t.Fatal("old admission history changed", e)
	}
}
