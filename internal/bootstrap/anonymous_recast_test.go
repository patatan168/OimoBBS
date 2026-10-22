// 確認済みIP/ホストの再発行待機・正常更新・署名・境界・再起動を検査する。
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/textcodec"
	"strings"
	"testing"
	"time"
)

// prepareRecastHost は実DNSを使わず、PTRと正引きが一致したcacheだけを準備する。
func prepareRecastHost(t *testing.T, repo *Repository, ip netip.Addr, host string, forward netip.Addr) {
	t.Helper()
	repo.networkHosts.Close()
	repo.networkHosts = identity.NewHostCache(denialHostResolver{host, forward})
	repo.networkHosts.Resolve(context.Background(), ip)
}

func TestAnonymousRecastSameOriginAndRecovery(t *testing.T) {
	cfg, repo, _, _ := anonymousFixture(t, "required")
	ip := netip.MustParseAddr("153.140.37.173")
	prepareRecastHost(t, repo, ip, "subscriber.example.jp", ip)
	now := time.Now()
	clock := func() time.Time { return now }
	first, err := repo.anonymousCookie("", ip, clock)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := repo.anonymous.verify(first.Value, now)
	if err != nil || initial.ReadyAt != 0 {
		t.Fatal("initial issue", err)
	}
	for range 8 {
		if _, err := repo.anonymousCookie("", ip, clock); err != nil {
			t.Fatal(err)
		}
	}
	second, err := repo.anonymousCookie("", ip, clock)
	if err != nil {
		t.Fatal(err)
	}
	reissued, err := repo.anonymous.verify(second.Value, now)
	if err != nil || reissued.ID == initial.ID || reissued.ReadyAt != now.Unix()+600 {
		t.Fatal("reissue", err)
	}
	var limited *abuse.RateLimited
	err = anonymousWait(reissued, 0, now.Truncate(time.Second))
	if !errors.Is(err, ErrAnonymousRecast) || !errors.As(err, &limited) || limited.RetryAfter != 600 {
		t.Fatal("wait", err)
	}
	seq := repo.site.State().Seq
	if cookie, err := repo.anonymousCookie(second.Value, ip, clock); cookie != nil || err != nil || repo.site.State().Seq != seq {
		t.Fatal("retry extended or reissued", err)
	}
	err = anonymousWait(reissued, 0, time.Unix(reissued.ReadyAt-1, 0))
	if !errors.As(err, &limited) || limited.RetryAfter != 1 {
		t.Fatal("last second", err)
	}
	if err = anonymousWait(reissued, 0, time.Unix(reissued.ReadyAt, 0)); err != nil {
		t.Fatal("exact readiness", err)
	}
	if err = anonymousWait(initial, 0, now); err != nil {
		t.Fatal("original cookie affected", err)
	}
	var site siteState
	if err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); err != nil || site.MinimumReader != 70 {
		t.Fatal("reader", err)
	}
	for name, row := range repo.site.State().Rows {
		if strings.HasPrefix(name, "token_reissue:") && (strings.Contains(string(row.Value), ip.String()) || strings.Contains(string(row.Value), "subscriber.example.jp")) {
			t.Fatal("origin plaintext persisted")
		}
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal("restart", err)
	}
	defer repo.Close()
	if _, err = repo.anonymous.verify(second.Value, time.Now()); err != nil {
		t.Fatal("recast signature after restart", err)
	}
	prepareRecastHost(t, repo, ip, "subscriber.example.jp", ip)
	third, err := repo.anonymousCookie("", ip, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	thirdToken, err := repo.anonymous.verify(third.Value, time.Now())
	if err != nil || thirdToken.ReadyAt == 0 {
		t.Fatal("issue history lost after restart", err)
	}
}

func TestAnonymousRecastOriginAndHourBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, host          string
		offset              time.Duration
		differentIP, forged bool
		wait                bool
	}{
		{"within-hour", "subscriber.example.jp", time.Hour - time.Nanosecond, false, false, true},
		{"exact-hour", "subscriber.example.jp", time.Hour, false, false, false},
		{"different-host", "other.example.jp", time.Second, false, false, false},
		{"different-ip", "subscriber.example.jp", time.Second, true, false, false},
		{"unconfirmed-host", "subscriber.example.jp", time.Second, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, repo, _, _ := anonymousFixture(t, "required")
			defer repo.Close()
			ip := netip.MustParseAddr("153.140.37.173")
			prepareRecastHost(t, repo, ip, "subscriber.example.jp", ip)
			now := time.Now()
			clock := func() time.Time { return now }
			if _, err := repo.anonymousCookie("", ip, clock); err != nil {
				t.Fatal(err)
			}
			for range 8 {
				if _, err := repo.anonymousCookie("", ip, clock); err != nil {
					t.Fatal(err)
				}
			}
			if tc.differentIP {
				ip = netip.MustParseAddr("153.140.37.174")
			}
			forward := ip
			if tc.forged {
				forward = netip.MustParseAddr("8.8.8.8")
			}
			prepareRecastHost(t, repo, ip, tc.host, forward)
			now = now.Add(tc.offset)
			cookie, err := repo.anonymousCookie("", ip, clock)
			if err != nil {
				t.Fatal(err)
			}
			token, err := repo.anonymous.verify(cookie.Value, now)
			if err != nil || (token.ReadyAt != 0) != tc.wait {
				t.Fatal("origin/hour boundary", token.ReadyAt, err)
			}
		})
	}
}

func TestAnonymousRecastNormalRenewal(t *testing.T) {
	_, repo, _, _ := anonymousFixture(t, "required")
	defer repo.Close()
	ip := netip.MustParseAddr("153.140.37.173")
	prepareRecastHost(t, repo, ip, "subscriber.example.jp", ip)
	now := time.Now()
	if _, err := repo.anonymousCookie("", ip, func() time.Time { return now }); err != nil {
		t.Fatal(err)
	}
	old := abuse.Anon{ID: domain.NewID(), Generation: 1, Issued: now.Add(-24 * 24 * time.Hour).Unix(), Expires: now.Add(6 * 24 * time.Hour).Unix()}
	raw, err := abuse.IssueAnon(old, repo.anonymous.key[:], 4)
	if err != nil {
		t.Fatal(err)
	}
	seq := repo.site.State().Seq
	cookie, err := repo.anonymousCookie(raw, ip, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	renewed, err := repo.anonymous.verify(cookie.Value, now)
	if err != nil || renewed.ID != old.ID || renewed.ReadyAt != 0 || renewed.Expires <= old.Expires || repo.site.State().Seq != seq {
		t.Fatal("normal renewal consumed issue history or recast", err)
	}
}

func TestAnonymousRecastProgressiveSteps(t *testing.T) {
	_, repo, _, _ := anonymousFixture(t, "required")
	defer repo.Close()
	ip := netip.MustParseAddr("153.140.37.173")
	prepareRecastHost(t, repo, ip, "subscriber.example.jp", ip)
	now := time.Now()
	for count := 1; count <= 12; count++ {
		cookie, err := repo.anonymousCookie("", ip, func() time.Time { return now })
		if err != nil {
			t.Fatal(err)
		}
		token, err := repo.anonymous.verify(cookie.Value, now)
		if err != nil {
			t.Fatal(err)
		}
		want := int64(0)
		if count >= 10 {
			want = now.Unix() + int64(count-9)*600
		}
		if token.ReadyAt != want {
			t.Fatal("progressive wait", count, token.ReadyAt, want)
		}
	}
}

func TestAnonymousRecastHTTPAndAcceptedRetry(t *testing.T) {
	_, repo, site, owner := anonymousFixture(t, "required")
	defer repo.Close()
	ip := netip.MustParseAddr("153.140.37.173")
	prepareRecastHost(t, repo, ip, "subscriber.example.jp", ip)
	now := time.Now().Truncate(time.Second).Add(time.Second)
	clock := func() time.Time { return now }
	if _, err := repo.anonymousCookie("", ip, clock); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		if _, err := repo.anonymousCookie("", ip, clock); err != nil {
			t.Fatal(err)
		}
	}
	cookie, err := repo.anonymousCookie("", ip, clock)
	if err != nil {
		t.Fatal(err)
	}
	token, err := repo.anonymous.verify(cookie.Value, now)
	if err != nil {
		t.Fatal(err)
	}
	repo.posting[owner].clock = clock
	server, request, cookies := anonymousHTTP(t, repo, site)
	defer server.Close()
	cookies["oimo_anon"] = cookie
	fields := url.Values{"bbs": {"news"}, "subject": {"待機試験"}, "MESSAGE": {"WAIT-THEN-ACCEPT"}, "oimo_request_id": {"recast-http-post-0001"}}
	// 規約同意後は、Cookie再発行の待機条件へ直接進む。
	response, body := request("POST", "/test/bbs.cgi", fields)
	if response.StatusCode != 200 || !strings.Contains(body, "2ch_X:cookie") {
		t.Fatal("consent", response.StatusCode, body)
	}
	response, body = request("POST", "/test/bbs.cgi", fields)
	decoded, _ := textcodec.Decode([]byte(body))
	if response.StatusCode != 429 || response.Header.Get("Retry-After") != "600" || !strings.Contains(decoded, "投稿間隔を空けて") || strings.Contains(decoded, "再発行") || strings.Contains(decoded, "匿名Cookie") {
		t.Fatal("HTTP recast response", response.StatusCode)
	}
	if cookies["oimo_anon"].Value != cookie.Value {
		t.Fatal("waiting replaced Cookie")
	}
	now = now.Add(time.Minute)
	response, _ = request("POST", "/test/bbs.cgi", fields)
	if response.StatusCode != 429 || response.Header.Get("Retry-After") != "540" {
		t.Fatal("retry extended waiting", response.StatusCode)
	}
	now = time.Unix(token.ReadyAt, 0)
	// 待機後も内容確認の往復なしで投稿する。
	response, body = request("POST", "/test/bbs.cgi", fields)
	decoded, _ = textcodec.Decode([]byte(body))
	if response.StatusCode != http.StatusOK || !strings.Contains(decoded, "投稿を受け付けました。") {
		t.Fatal("post after waiting", response.StatusCode)
	}
	response, body = request("POST", "/test/bbs.cgi", fields)
	decoded, _ = textcodec.Decode([]byte(body))
	if response.StatusCode != http.StatusOK || !strings.Contains(decoded, "同一内容を受理済みです。") {
		t.Fatal("accepted retry charged again", response.StatusCode)
	}
}
