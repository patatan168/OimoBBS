// 検出履歴の容量不足とIPv6のアドレス変更が、通常投稿や通報の独立性を壊さないことを検査する。
package bootstrap

import (
	"errors"
	"fmt"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
	"testing"
	"time"
)

func TestAbuseGuardFullHistoryHTTPAvailability(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "available", "通常投稿")
	if err != nil {
		t.Fatal(err)
	}
	c := newAdminClient(t, repo)
	defer c.server.Close()
	c.login(adminTestSecret)
	settings := defaultAbuseGuard()
	settings.Similar.Mode, settings.Flood.Mode = "reject", "reject"
	saveGuardSettings(t, c, settings, "availability-guard-settings")
	c.server.Close()
	at := domain.Time(time.Now().UnixNano())
	repo.guard.mu.Lock()
	for i := range guardHistoryLimit {
		e := guardTestEntry(domain.NewID(), uint64(i+1), fmt.Sprint(i), i, at)
		repo.guard.remember(e)
	}
	// 復旧時に履歴を切り詰めた場合も、欠けた履歴だけで投稿を拒否しない。
	repo.guard.overflowUntil = at + guardHistorySeconds*1e9
	repo.guard.mu.Unlock()
	server := formServer(t, repo, siteID(repo.site.State()), board.ID)
	fields := url.Values{"bbs": {"available"}, "subject": {"通常の話題"}, "MESSAGE": {"他の板の検出履歴が満杯でも保存できる本文"}, "oimo_request_id": {"availability-normal-post"}}
	result, err := sendForm(server, fields)
	server.Close()
	if err != nil || !result.Accepted {
		t.Fatal("unrelated HTTP post blocked", result, err)
	}
	repo.guard.mu.Lock()
	count := len(repo.guard.entries)
	events := append([]GuardEvent(nil), repo.guard.events...)
	repo.guard.mu.Unlock()
	if count != guardHistoryLimit || len(events) == 0 || events[len(events)-1].Rejected {
		t.Fatal("history must remain bounded and observable", count, events)
	}
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	server = formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer server.Close()
	result, err = sendForm(server, fields)
	if err != nil || !result.Accepted || !result.Duplicate {
		t.Fatal("accepted post did not survive restart", result, err)
	}
}

func TestAutoReportIPv6NetworkVotes(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "vote", "通報の独立性")
	if err != nil {
		t.Fatal(err)
	}
	b := repo.posting[board.ID]
	repo.autoReportVotes = make(map[autoReportTarget][]autoReportVote)
	subject := domain.Hash{99}
	at := domain.Time(time.Now().UnixNano())
	for i, ip := range []string{"2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2::3", "2001:0db8:0001:0002::4", "2001:db8:1:3::1"} {
		message := autoReportMessage{Reference: autoReportReference{"vote", 1, 1}, Operation: domain.NewID(), Reporter: app.EvidencePostIdentity{IP: ip, Subject: domain.Hash{byte(i + 1)}}, At: at}
		if err := repo.recordAutoReport(b, subject, message, at); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(repo.autoReportVotes[autoReportTarget{board.ID, subject}]); got != 2 || len(b.denials) != 0 {
		t.Fatal("one IPv6 network created independent votes", got, len(b.denials))
	}
}

func TestAutoReportNetworkBoundaries(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"2001:db8:1:2::1", "2001:db8:1:2::/64"},
		{"2001:0db8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "2001:db8:1:3::/64"},
		{"192.0.2.1", "192.0.2.1"},
		{"192.0.2.2", "192.0.2.2"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"", ""}, {"invalid", ""}, {"fe80::1%eth0", ""},
	} {
		if got := autoReportNetwork(tc.raw); got != tc.want {
			t.Fatalf("%q: got %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestAbuseGuardFullHistoryKeepsTargetedRejection(t *testing.T) {
	for _, mode := range []string{"similar", "flood"} {
		t.Run(mode, func(t *testing.T) {
			at := domain.Time(time.Now().UnixNano())
			g := &abuseGuard{settings: defaultAbuseGuard()}
			g.settings.Similar.Mode, g.settings.Flood.Mode = "reject", "reject"
			g.settings.Similar.MatchPosts = 2
			g.settings.Flood.ThreadPosts = 2
			for i := range guardHistoryLimit {
				g.remember(guardTestEntry(domain.NewID(), uint64(i+1), "古い履歴", i, at-599e9))
			}
			board := domain.NewID()
			for i := range 2 {
				g.remember(guardTestEntry(board, 1, "繰り返している広告の本文", i+1, at))
			}
			candidate := guardTestEntry(board, 1, "繰り返している広告の本文", 3, at)
			if mode == "similar" {
				candidate.board = domain.NewID()
			} else {
				candidate.signature = guardBodySignature("内容を変えた投稿")
			}
			var limited *abuse.RateLimited
			if err := g.check(candidate); !errors.Is(err, ErrAbuseGuard) || !errors.As(err, &limited) {
				t.Fatal("retained history did not reject attack", err)
			}
			candidate.board = domain.NewID()
			candidate.signature = guardBodySignature("無関係な利用者の通常の会話")
			if err := g.check(candidate); err != nil {
				t.Fatal("unrelated post blocked", err)
			}
			if len(g.entries) != guardHistoryLimit || g.events[len(g.events)-1].Rejected {
				t.Fatal("capacity observation must not reject or grow history")
			}
		})
	}
}
