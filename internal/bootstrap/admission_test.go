// 有効化の移行、実HTTPの429と再送、再起動後の消費復元を検証する。
package bootstrap

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAdmissionHTTPMigrationAndRecovery(t *testing.T) {
	cfg := testConfig(t)
	report, e := Initialize(cfg, "規制試験")
	if e != nil {
		t.Fatal(e)
	}
	repo, e := OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	defer func() {
		if repo != nil {
			repo.Close()
		}
	}()
	board, e := repo.CreateBoard(context.Background(), "news", "試験板")
	if e != nil {
		t.Fatal(e)
	}
	oldServer := formServer(t, repo, report.SiteID, board.ID)
	old, e := sendForm(oldServer, url.Values{"bbs": {"news"}, "subject": {"旧投稿"}, "MESSAGE": {"有効化前"}, "oimo_request_id": {"before-activation-0001"}})
	oldServer.Close()
	if e != nil || !old.Accepted {
		t.Fatal("old post", e, old)
	}
	before, e := repo.rateHistory()
	if e != nil || len(before) != 1 || len(before[0].record.Keys) != 0 {
		t.Fatal("old history", e)
	}
	policy, e := repo.EnableAdmission()
	if e != nil {
		t.Fatal(e)
	}
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal(e)
	}
	again, e := repo.EnableAdmission()
	if e != nil || !reflect.DeepEqual(policy, again) {
		t.Fatal("activation reset", e)
	}
	after, e := repo.rateHistory()
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("old history changed", e)
	}
	var server *httptest.Server
	start := func() {
		observer, e := evidence.NewHTTPObserver(report.SiteID, domain.NewID(), "admission-test")
		if e != nil {
			t.Fatal(e)
		}
		server = httptest.NewUnstartedServer(repo.SiteWebHandler(observer))
		server.Config.ConnContext = observer.ConnContext
		server.Start()
		server.Client().CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	start()
	defer func() { server.Close() }()
	cookies := map[string]*http.Cookie{}
	request := func(method, path string, fields url.Values) (*http.Response, string) {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(fields.Encode()))
		req.Host = "127.0.0.1:9080"
		if method == "POST" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
			req.Header.Set("Origin", cfg.Public.BaseURL)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, e := server.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		raw, e := io.ReadAll(res.Body)
		if e != nil {
			t.Fatal(e)
		}
		for _, c := range res.Cookies() {
			cookies[c.Name] = c
		}
		return res, string(raw)
	}
	// 確認だけでは受理履歴を作らず、同一内容の確認後に初回burstを使える。
	fields := url.Values{"bbs": {"news"}, "subject": {"規制後"}, "MESSAGE": {"本文"}, "oimo_request_id": {"after-activation-0001"}}
	res, _ := request("POST", "/test/bbs.cgi", fields)
	history, _ := repo.rateHistory()
	if res.StatusCode != 200 || len(history) != 1 {
		t.Fatal("confirmation consumed acceptance")
	}
	res, _ = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 {
		t.Fatal("create", res.StatusCode)
	}
	history, _ = repo.rateHistory()
	if len(history) != 2 || len(history[1].record.Keys) != 3 {
		t.Fatal("missing acceptance keys")
	}
	original := fields.Encode()
	fields.Set("oimo_request_id", "after-activation-0002")
	res, _ = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" {
		t.Fatal("legacy limit", res.StatusCode)
	}
	fields, _ = url.ParseQuery(original)
	res, _ = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 200 {
		t.Fatal("receipt blocked", res.StatusCode)
	}
	server.Close()
	if e = repo.Close(); e != nil {
		t.Fatal(e)
	}
	repo, e = OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("recover", e)
	}
	start()
	fields.Set("oimo_request_id", "after-activation-0003")
	res, _ = request("POST", "/test/bbs.cgi", fields)
	if res.StatusCode != 429 {
		t.Fatal("restart reset limit", res.StatusCode)
	}
	// Web側も429で本文と要求IDを保持する。
	_, page := request("GET", "/web/post?bbs=news", nil)
	web := pageFields(page)
	web.Set("subject", "Web確認")
	web.Set("MESSAGE", "保持する本文")
	request("POST", "/web/post?bbs=news", web)
	res, page = request("POST", "/web/post?bbs=news", web)
	if res.StatusCode != 429 || res.Header.Get("Retry-After") == "" || pageFields(page).Get("MESSAGE") != web.Get("MESSAGE") || pageFields(page).Get("oimo_request_id") != web.Get("oimo_request_id") {
		t.Fatal("web retry fields", res.StatusCode)
	}
	history, _ = repo.rateHistory()
	if len(history) != 2 {
		t.Fatal("rejected/duplicate post persisted")
	}
}

func TestAdmissionKeysClockAndRelease(t *testing.T) {
	now := time.Unix(1800000000, 0)
	a := &admission{policy: initialAdmission(now), limits: abuse.NewLimiter(100)}
	owner := domain.NewID()
	ip := netip.MustParseAddr("192.0.2.1")
	for range 3 {
		ticket, keys, at, e := a.reserve(owner, ip, false, func() time.Time { return now })
		if e != nil {
			t.Fatal(e)
		}
		record := app.RateRecord{At: domain.Time(at.UnixNano()), IP: ip.String(), Keys: keys}
		if e = a.validate(owner, record); e != nil {
			t.Fatal(e)
		}
		record.Keys = keys[:2]
		if a.validate(owner, record) == nil {
			t.Fatal("missing key accepted")
		}
		if e = a.limits.Commit(ticket); e != nil {
			t.Fatal(e)
		}
	}
	_, _, _, e := a.reserve(owner, ip, false, func() time.Time { return now })
	var limited *abuse.RateLimited
	if !errors.As(e, &limited) || limited.RetryAfter != 1 {
		t.Fatal("reply limit", e)
	}
	_, _, _, e = a.reserve(owner, ip, false, func() time.Time { return now.Add(-time.Nanosecond) })
	if !errors.Is(e, abuse.ErrRateClock) {
		t.Fatal("clock", e)
	}
	ticket, _, _, e := a.reserve(owner, ip, false, func() time.Time { return now.Add(time.Second) })
	if e != nil {
		t.Fatal(e)
	}
	if e = a.limits.Release(ticket); e != nil {
		t.Fatal(e)
	}
	ticket, _, _, e = a.reserve(owner, ip, false, func() time.Time { return now.Add(time.Second) })
	if e != nil {
		t.Fatal("release", e)
	}
	if e = a.limits.Uncertain(ticket); e != nil {
		t.Fatal(e)
	}
	if a.limits.Release(ticket) == nil {
		t.Fatal("uncertain refunded")
	}
}

func TestAdmissionAttemptPeerAndNoBodyRead(t *testing.T) {
	now := time.Now()
	a := &admission{policy: initialAdmission(now.Add(-time.Second)), limits: abuse.NewLimiter(100)}
	for range 20 {
		if e := a.attempt("192.0.2.1:1234", func() time.Time { return now }); e != nil {
			t.Fatal(e)
		}
	}
	var limited *abuse.RateLimited
	if e := a.attempt("[::ffff:192.0.2.1]:5678", func() time.Time { return now }); !errors.As(e, &limited) {
		t.Fatal("mapped peer bypass", e)
	}
	// 時計逆行を注入し、試行制限の異常時にも本文を読む前に拒否することを確認する。
	a.lastAttempt = domain.Time(now.Add(time.Hour).UnixNano())
	repo := &Repository{admission: a}
	req := httptest.NewRequest("POST", "http://example.test/test/bbs.cgi", panicBody{})
	req.RemoteAddr = "192.0.2.1:9876"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	w := httptest.NewRecorder()
	if repo.admitAttempt(w, req) || w.Code != 503 {
		t.Fatal("attempt gate bypass")
	}
}

type panicBody struct{}

func (panicBody) Read([]byte) (int, error) { panic("rejected request body read") }

// 保存前の検証失敗は返却し、journal作成の結果不明は予約を保持して板を停止する。
func TestAdmissionStorageFailureOwnership(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "not_written", true: "unknown"}[uncertain], func(t *testing.T) {
			cfg := testConfig(t)
			report, e := Initialize(cfg, "保存障害")
			if e != nil {
				t.Fatal(e)
			}
			repo, e := OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			defer func() {
				if repo != nil {
					repo.Close()
				}
			}()
			board, e := repo.CreateBoard(context.Background(), "news", "試験板")
			if e != nil {
				t.Fatal(e)
			}
			if _, e = repo.EnableAdmission(); e != nil {
				t.Fatal(e)
			}
			if e = repo.Close(); e != nil {
				t.Fatal(e)
			}
			repo, e = OpenPostingRepository(cfg, postcapture.Validate)
			if e != nil {
				t.Fatal(e)
			}
			b := repo.posting[board.ID]
			if uncertain {
				now := time.Now()
				if _, e = b.journal(now); e != nil {
					t.Fatal(e)
				}
				if e = os.Mkdir(filepath.Join(b.evidenceDir, now.UTC().Format("20060102")), 0700); e != nil {
					t.Fatal(e)
				}
			}
			server := formServer(t, repo, report.SiteID, board.ID)
			defer server.Close()
			fields := url.Values{"bbs": {"news"}, "subject": {"保存境界"}, "MESSAGE": {"本文"}, "oimo_request_id": {"storage-ownership-0001"}}
			if !uncertain {
				fields.Set("MESSAGE", strings.Repeat("x", 4097))
			}
			result, e := sendForm(server, fields)
			if e != nil || result.Accepted {
				t.Fatal("fault accepted", e)
			}
			ticket, _, _, e := repo.admission.reserve(board.ID, netip.MustParseAddr("127.0.0.1"), true, time.Now)
			if uncertain {
				var limited *abuse.RateLimited
				if !b.stopped || !errors.As(e, &limited) {
					t.Fatal("unknown reservation refunded", e)
				}
			} else {
				if e != nil {
					t.Fatal("not-written reservation leaked", e)
				}
				if e = repo.admission.limits.Release(ticket); e != nil {
					t.Fatal(e)
				}
				fields.Set("MESSAGE", "訂正済み")
				result, e = sendForm(server, fields)
				if e != nil || !result.Accepted {
					t.Fatal("corrected post rejected", e)
				}
			}
		})
	}
}
