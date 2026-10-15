// 類似度・ランダム埋め立て・主体変更・有界履歴・取消と期限境界を検査する。
package bootstrap

import (
	"errors"
	"fmt"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"strings"
	"testing"
	"time"
)

func TestAbuseGuardSimilar(t *testing.T) {
	base := "広告投稿です。0123456789abcdefghijklmnopqrstuvwxyz。繰り返し投稿しないでください。"
	for _, tc := range []struct {
		body string
		want bool
	}{
		{base, true}, {" \n" + base + "　", true}, {base + "1", true}, {"全く別の話題について会話する文章です。今日は天気がよいですね。", false},
	} {
		if got := guardSimilar(guardBodySignature(base), guardBodySignature(tc.body), 12, 90); got != tc.want {
			t.Fatalf("%q: %v", tc.body, got)
		}
	}
	if guardSimilar(guardBodySignature("はい"), guardBodySignature("はい！"), 12, 50) {
		t.Fatal("short text similarity")
	}
	if !guardSimilar(guardBodySignature("はい"), guardBodySignature("はい"), 12, 90) {
		t.Fatal("short exact equality")
	}
	if !guardSimilar(guardBodySignature("hello\n world"), guardBodySignature("hello　\tworld"), 3, 100) {
		t.Fatal("Unicode whitespace normalization")
	}
	if guardBodySignature(strings.Repeat("a", 32768)).oversized {
		t.Fatal("repetitive long text not bounded by unique grams")
	}
	var long strings.Builder
	for i := 0; i < 5000; i++ {
		long.WriteRune(rune(0x400 + i))
	}
	if !guardBodySignature(long.String()).oversized {
		t.Fatal("signature memory bound")
	}
}
func guardTestEntry(board domain.ID, key uint64, body string, n int, at domain.Time) guardEntry {
	return guardEntry{id: domain.NewID(), board: board, thread: key, number: uint32(n), at: at, ip: domain.Hash{byte(n)}, token: domain.Hash{byte(n + 10)}, signature: guardBodySignature(body)}
}
func TestAbuseGuardDetectionAndModes(t *testing.T) {
	at := domain.Time(time.Now().UnixNano())
	a, b := domain.NewID(), domain.NewID()
	g := &abuseGuard{settings: defaultAbuseGuard()}
	g.settings.Similar.Mode = "reject"
	g.settings.Similar.MatchPosts = 2
	g.settings.Flood.Mode = "off"
	for i := 1; i <= 2; i++ {
		e := guardTestEntry(a, 1, "同じ広告の本文を何回も書く", i, at)
		if err := g.check(e); err != nil {
			t.Fatal(err)
		}
		g.remember(e)
	}
	third := guardTestEntry(b, 2, "同じ広告の本文を何回も書く", 3, at)
	var limited *abuse.RateLimited
	if err := g.check(third); !errors.As(err, &limited) || len(g.entries) != 2 {
		t.Fatal("cross-board similarity", err)
	}
	g.settings.Similar.Mode = "observe"
	if err := g.check(third); err != nil {
		t.Fatal("observe rejects", err)
	}
	if len(g.events) != 2 || g.events[1].Rejected {
		t.Fatal("observe missing")
	}
	g.settings.Similar.Mode = "off"
	if err := g.check(third); err != nil || len(g.events) != 2 {
		t.Fatal("off detects", err)
	}
	g.settings.Similar.Mode = "reject"
	third.cap = true
	if err := g.check(third); err != nil {
		t.Fatal("authenticated cap exemption", err)
	}
	g.settings.ExemptCaps = false
	if err := g.check(third); !errors.As(err, &limited) {
		t.Fatal("disabled cap exemption", err)
	}
	g.prune(at+301e9, nil)
	third.cap = false
	third.at = at + 301e9
	if err := g.check(third); err != nil {
		t.Fatal("window expiry", err)
	}
}
func TestAbuseGuardDistributedRandomFlood(t *testing.T) {
	at := domain.Time(time.Now().UnixNano())
	a, b := domain.NewID(), domain.NewID()
	g := &abuseGuard{settings: defaultAbuseGuard()}
	g.settings.Similar.Mode = "off"
	g.settings.Flood.Mode = "reject"
	g.settings.Flood.ThreadPosts = 4
	for i := 1; i <= 4; i++ {
		e := guardTestEntry(a, 123, fmt.Sprintf("random %d unrelated", i), i, at)
		if err := g.check(e); err != nil {
			t.Fatal(err)
		}
		g.remember(e)
	}
	next := guardTestEntry(a, 123, "違う本文・違うIP・違うCookie", 5, at)
	var limited *abuse.RateLimited
	if err := g.check(next); !errors.As(err, &limited) {
		t.Fatal("distributed flood accepted", err)
	}
	next.board = b
	if err := g.check(next); err != nil {
		t.Fatal("other board same key rejected", err)
	}
	next.board = a
	next.thread = 124
	if err := g.check(next); err != nil {
		t.Fatal("other thread rejected", err)
	}
	next.at = at + 30e9
	next.thread = 123
	g.prune(next.at, nil)
	if err := g.check(next); err != nil {
		t.Fatal("exact expiry", err)
	}
}
func TestAbuseGuardSubjectRotationAndShare(t *testing.T) {
	at := domain.Time(time.Now().UnixNano())
	owner := domain.NewID()
	g := &abuseGuard{settings: defaultAbuseGuard()}
	g.settings.Similar.Mode = "off"
	g.settings.Flood.Mode = "reject"
	g.settings.Flood.SubjectPosts = 2
	for i := 1; i <= 2; i++ {
		e := guardTestEntry(domain.NewID(), uint64(i), fmt.Sprint(i), i, at)
		e.ip = domain.Hash{42}
		g.remember(e)
	}
	next := guardTestEntry(owner, 3, "random", 3, at)
	next.ip = domain.Hash{42}
	var limited *abuse.RateLimited
	if err := g.check(next); !errors.As(err, &limited) {
		t.Fatal("Cookie rotation bypass", err)
	}
	for i := range g.entries {
		g.entries[i].ip = domain.Hash{byte(i + 1)}
		g.entries[i].token = domain.Hash{99}
	}
	next.ip = domain.Hash{70}
	next.token = domain.Hash{99}
	if err := g.check(next); !errors.As(err, &limited) {
		t.Fatal("IP rotation bypass", err)
	}
	g = &abuseGuard{settings: defaultAbuseGuard()}
	g.settings.Similar.Mode = "off"
	g.settings.Flood.Mode = "reject"
	g.settings.Flood.ShareMinPosts = 3
	g.settings.Flood.SharePercent = 75
	for i := 1; i <= 2; i++ {
		e := guardTestEntry(owner, 1, fmt.Sprint(i), i, at)
		e.ip = next.ip
		g.remember(e)
	}
	next.board = owner
	next.thread = 1
	if err := g.check(next); !errors.As(err, &limited) {
		t.Fatal("thread monopolization", err)
	}
	for i := 4; i <= 6; i++ {
		g.remember(guardTestEntry(owner, 1, fmt.Sprint(i), i, at))
	}
	if err := g.check(next); err != nil {
		t.Fatal("normal conversation share", err)
	}
	board := &postingBoard{dedupKey: domain.Hash{1}, owner: owner}
	if board.guardIPSubject("2001:db8:1:2::1") != board.guardIPSubject("2001:db8:1:2::ffff") {
		t.Fatal("IPv6 /64 rotation")
	}
	if board.guardIPSubject("::ffff:192.0.2.1") != board.guardIPSubject("192.0.2.1") {
		t.Fatal("mapped IPv4 mismatch")
	}
}
func TestAbuseGuardPendingCancelCapacityAndDeletion(t *testing.T) {
	at := domain.Time(time.Now().UnixNano())
	owner := domain.NewID()
	g := &abuseGuard{settings: defaultAbuseGuard()}
	g.settings.Similar.MatchPosts = 1
	g.settings.Similar.Mode = "reject"
	g.settings.Flood.Mode = "off"
	first := guardTestEntry(owner, 1, "保存済み本文", 1, at)
	g.remember(first)
	pending := guardTestEntry(owner, 1, "未確定の候補", 2, at)
	pending.pending = true
	g.remember(pending)
	duplicate := pending
	duplicate.id = domain.NewID()
	if err := g.check(duplicate); err == nil {
		t.Fatal("pending omitted")
	}
	g.settle(pending.id, false)
	if err := g.check(duplicate); err != nil {
		t.Fatal("canceled counted", err)
	}
	for range 140 {
		e := guardTestEntry(owner, 1, "取り消される候補", 2, at)
		e.pending = true
		g.remember(e)
		g.settle(e.id, false)
	}
	if err := g.check(first); err == nil {
		t.Fatal("cancellation erased committed signatures")
	}
	g.prune(at, func(domain.ID, uint64, uint32) bool { return false })
	if len(g.entries) != 0 {
		t.Fatal("deleted signature retained")
	}
	g.settings.Flood.Mode = "reject"
	g.settings.Similar.Mode = "off"
	for i := 0; i < guardHistoryLimit; i++ {
		e := guardTestEntry(owner, uint64(i+1), "", i+1, at)
		g.remember(e)
	}
	if err := g.check(guardTestEntry(owner, 99999, "", 0, at)); err == nil {
		t.Fatal("full history bypass")
	}
	g.settings.Flood.Mode = "observe"
	e := guardTestEntry(owner, 99999, "", 0, at)
	if err := g.check(e); err != nil {
		t.Fatal(err)
	}
	g.remember(e)
	if len(g.entries) != guardHistoryLimit || g.overflowUntil == 0 {
		t.Fatal("unbounded history")
	}
	if err := g.check(guardTestEntry(owner, 1, "", 0, at-1)); !errors.Is(err, abuse.ErrRateClock) {
		t.Fatal("clock rollback", err)
	}
}
func TestAbuseGuardRestoreBoundedAndNewest(t *testing.T) {
	var r guardRestore
	at := domain.Time(time.Now().UnixNano())
	owner := domain.NewID()
	for i := 5000; i > 0; i-- {
		e := guardTestEntry(owner, 1, "", i, at+domain.Time(i))
		e.signature = guardSignature{}
		r.add(e, fmt.Sprint(i))
	}
	entries := r.finish()
	if len(entries) != 4096 || len(r.signatures) != 128 || r.overflow == 0 {
		t.Fatal("restore bounds")
	}
	signatures := 0
	for _, e := range entries {
		if e.signature.exact != ([32]byte{}) {
			signatures++
			if e.number < 4873 {
				t.Fatal("older signature retained")
			}
		}
	}
	if signatures != 128 {
		t.Fatal(signatures)
	}
}

// 満杯時も未確定候補を予約し、取消が失われた実投稿の期限を延ばさないことを確認する。
func TestAbuseGuardOverflowPendingCancellation(t *testing.T) {
	at := domain.Time(time.Now().UnixNano())
	owner := domain.NewID()
	g := &abuseGuard{settings: defaultAbuseGuard()}
	for i := 0; i < guardHistoryLimit; i++ {
		g.remember(guardTestEntry(owner, uint64(i+1), "本文", i+1, at-100e9))
	}
	pending := guardTestEntry(owner, 99999, "未確定", 0, at)
	pending.pending = true
	if err := g.check(pending); err != nil {
		t.Fatal(err)
	}
	g.remember(pending)
	if g.entries[len(g.entries)-1].id != pending.id {
		t.Fatal("pending not reserved")
	}
	g.settle(pending.id, false)
	if len(g.entries) != guardHistoryLimit-1 || g.overflowUntil != at+500e9 {
		t.Fatal("failed post extended history", len(g.entries), g.overflowUntil)
	}
}
