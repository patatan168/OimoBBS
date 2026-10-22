// 本文を追加保存せず、有界の類似文索引と投稿数で連投・スレッド埋め立てを検出する。
package bootstrap

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// ErrAbuseGuard は追加の連投・埋め立て判定による拒否。Retry-Afterは内部のRateLimitedから取得する。
var ErrAbuseGuard = errors.New("abuse guard rejected posting")

const guardHistoryLimit = 4096
const guardSignatureLimit = 4096
const guardHistorySeconds = 600

// SimilarSettings は全板を横断する類似本文検出条件。Modeはoff/observe/reject。
type SimilarSettings struct {
	Mode             string `json:"mode"`
	WindowSeconds    int    `json:"window_seconds"`
	SamplePosts      int    `json:"sample_posts"`
	ThresholdPercent int    `json:"threshold_percent"`
	MatchPosts       int    `json:"match_posts"`
	MinRunes         int    `json:"min_runes"`
}

// FloodSettings はランダム本文・複数主体にも適用するスレッド集中と主体占有の条件。
type FloodSettings struct {
	Mode          string `json:"mode"`
	WindowSeconds int    `json:"window_seconds"`
	ThreadPosts   int    `json:"thread_posts"`
	SubjectPosts  int    `json:"subject_posts"`
	ShareMinPosts int    `json:"share_min_posts"`
	SharePercent  int    `json:"share_percent"`
}

// AbuseGuardSettings は掲示板全体で稼働中変更できる追加対策。CAP免除は認証成功時だけ有効。
type AbuseGuardSettings struct {
	BotMode          string            `json:"bot_mode,omitempty"`
	Similar          SimilarSettings   `json:"similar"`
	Flood            FloodSettings     `json:"flood"`
	ExemptCaps       bool              `json:"exempt_caps"`
	Rates            AdminRateSettings `json:"rates"`
	TokenWaitSeconds uint32            `json:"token_wait_seconds"`
}

// defaultAbuseGuard は類似文・埋め立てを検出のみ、不正フォームの反復を自動停止にする。
func defaultAbuseGuard() AbuseGuardSettings {
	return AbuseGuardSettings{"reject", SimilarSettings{"observe", 300, 50, 90, 3, 12}, FloodSettings{"observe", 30, 100, 30, 15, 80}, true, defaultRateSettings(), 0}
}
func guardModeValid(v string) bool { return v == "off" || v == "observe" || v == "reject" }

// validate は保存前・復旧時とも比較費用と整数演算の範囲を制限する。
func (v AbuseGuardSettings) validate() error {
	s, f := v.Similar, v.Flood
	if !guardModeValid(effectiveBotMode(v.BotMode)) || v.Rates.validate() != nil || v.TokenWaitSeconds > 3600 {
		return fmt.Errorf("invalid global posting settings")
	}
	if !guardModeValid(s.Mode) || s.WindowSeconds < 1 || s.WindowSeconds > 600 || s.SamplePosts < 1 || s.SamplePosts > 128 || s.ThresholdPercent < 50 || s.ThresholdPercent > 100 || s.MatchPosts < 1 || s.MatchPosts > s.SamplePosts || s.MinRunes < 3 || s.MinRunes > 1000 || !guardModeValid(f.Mode) || f.WindowSeconds < 1 || f.WindowSeconds > 600 || f.ThreadPosts < 2 || f.ThreadPosts > 4000 || f.SubjectPosts < 2 || f.SubjectPosts > 4000 || f.ShareMinPosts < 2 || f.ShareMinPosts > 4000 || f.SharePercent < 50 || f.SharePercent > 100 {
		return fmt.Errorf("invalid abuse guard settings")
	}
	return nil
}

type guardSignature struct {
	exact     [32]byte
	grams     []uint64
	runes     int
	oversized bool
}
type guardEntry struct {
	id        domain.ID
	board     domain.ID
	thread    uint64
	number    uint32
	at        domain.Time
	ip, token domain.Hash
	signature guardSignature
	cap       bool
	pending   bool
}

// GuardEvent は本文・IP・主体識別子を含まない、管理者向けの短時間検出記録。
type GuardEvent struct {
	At         string    `json:"at"`
	Board      domain.ID `json:"board_id"`
	Thread     uint64    `json:"thread_key"`
	PostNumber uint32    `json:"post_number"`
	Reason     string    `json:"reason"`
	Count      int       `json:"count"`
	Rejected   bool      `json:"rejected"`
}
type abuseGuard struct {
	violations    map[domain.Hash]violationState
	mu            sync.Mutex
	configured    bool
	settings      AbuseGuardSettings
	entries       []guardEntry
	events        []GuardEvent
	floor         domain.Time
	overflowUntil domain.Time
}

// guardBodySignature は空白を畳み、最大4096個の3文字組だけを保持する。過大本文は明示する。
func guardBodySignature(body string) guardSignature {
	text := strings.Join(strings.Fields(body), " ")
	sig := guardSignature{exact: sha256.Sum256([]byte(text))}
	sig.runes = utf8.RuneCountInString(text)
	// 長い反復文でも全文rune配列や4096個分のmapを先に確保しない。
	unique := make(map[uint64]struct{}, min(sig.runes, 128))
	var previous [2]rune
	var lastGram [3]rune
	var encoded [utf8.UTFMax * 3]byte
	index := 0
	haveGram := false
	expanded := false
	for _, current := range text {
		if index < 2 {
			previous[index] = current
			index++
			continue
		}
		runes := [3]rune{previous[0], previous[1], current}
		previous = [2]rune{previous[1], current}
		if haveGram && runes == lastGram {
			continue
		}
		lastGram, haveGram = runes, true
		gram := utf8.AppendRune(encoded[:0], runes[0])
		gram = utf8.AppendRune(gram, runes[1])
		gram = utf8.AppendRune(gram, runes[2])
		sum := sha256.Sum256(gram)
		// 非反復文と分かったら一度だけ拡張し、mapの段階的な再確保を避ける。
		if len(unique) == 128 && !expanded {
			next := make(map[uint64]struct{}, min(sig.runes, guardSignatureLimit+1))
			for value := range unique {
				next[value] = struct{}{}
			}
			unique, expanded = next, true
		}
		unique[binary.LittleEndian.Uint64(sum[:8])] = struct{}{}
		if len(unique) > guardSignatureLimit {
			sig.oversized = true
			return sig
		}
	}
	sig.grams = make([]uint64, 0, len(unique))
	for h := range unique {
		sig.grams = append(sig.grams, h)
	}
	slices.Sort(sig.grams)
	return sig
}

// guardSimilar は文字3-gramのJaccard比を整数で比較する。短文・過大本文も完全一致を判定する。
func guardSimilar(a, b guardSignature, minimum, percent int) bool {
	if a.exact == b.exact {
		return true
	}
	if a.runes < minimum || b.runes < minimum || a.oversized || b.oversized {
		return false
	}
	// same*100 >= (len(a)+len(b)-same)*percent に必要な交差数。
	// 残りが全て一致しても届かない場合だけ打ち切り、閾値上の一致を保持する。
	needed := ((len(a.grams)+len(b.grams))*percent + 99 + percent) / (100 + percent)
	if needed == 0 || min(len(a.grams), len(b.grams)) < needed {
		return false
	}
	same, i, j := 0, 0, 0
	for i < len(a.grams) && j < len(b.grams) {
		if same+min(len(a.grams)-i, len(b.grams)-j) < needed {
			return false
		}
		switch {
		case a.grams[i] == b.grams[j]:
			same++
			if same >= needed {
				return true
			}
			i++
			j++
		case a.grams[i] < b.grams[j]:
			i++
		default:
			j++
		}
	}
	return false
}

// guardIPSubject はIPv4アドレスとIPv6 /64を共通のサイト内HMACに変換する。
func (b *postingBoard) guardIPSubject(raw string) domain.Hash {
	ip, e := netip.ParseAddr(raw)
	if e != nil {
		return domain.Hash{}
	}
	ip = ip.Unmap()
	value := ip.String()
	if ip.Is6() {
		value = netip.PrefixFrom(ip, 64).Masked().String()
	}
	return identity.MAC(b.dedupKey[:], "oimo/abuse-guard-ip/v1", []byte(value))
}

// prune は期限外・削除済み投稿の署名を除去する。pendingは所有列内の未確定候補。
func (g *abuseGuard) prune(now domain.Time, visible func(domain.ID, uint64, uint32) bool) {
	out := g.entries[:0]
	for _, e := range g.entries {
		if e.at > now-domain.Time(guardHistorySeconds)*1e9 && (e.pending || visible == nil || visible(e.board, e.thread, e.number)) {
			out = append(out, e)
		}
	}
	clear(g.entries[len(out):])
	g.entries = out
	g.trimSignatures()
}

// trimSignatures は件数履歴を維持し、本文由来の索引だけを直近128投稿へ制限する。
func (g *abuseGuard) trimSignatures() {
	kept := 0
	for i := len(g.entries) - 1; i >= 0; i-- {
		if g.entries[i].pending {
			continue
		}
		kept++
		if kept > 128 {
			g.entries[i].signature = guardSignature{}
		}
	}
}

// check は現在候補を含む投稿数を比較し、拒否中も履歴を追加しない。
func (g *abuseGuard) check(e guardEntry) error {
	pending := 0
	for _, old := range g.entries {
		if old.pending {
			pending++
		}
	}
	if pending >= 128 {
		return ErrPostingCapacity
	}
	if e.at < g.floor {
		return abuse.ErrRateClock
	}
	g.floor = e.at
	if e.cap && g.settings.ExemptCaps {
		return nil
	}
	s, f := g.settings.Similar, g.settings.Flood
	if s.Mode != "off" {
		matches, seen := 0, 0
		for i := len(g.entries) - 1; i >= 0 && seen < s.SamplePosts; i-- {
			old := g.entries[i]
			if old.at <= e.at-domain.Time(s.WindowSeconds)*1e9 || old.cap && g.settings.ExemptCaps {
				continue
			}
			seen++
			if guardSimilar(e.signature, old.signature, s.MinRunes, s.ThresholdPercent) {
				matches++
			}
		}
		if matches >= s.MatchPosts {
			if err := g.hit(e, "類似本文の連投", matches+1, s.Mode, s.WindowSeconds); err != nil {
				return err
			}
		}
		if e.signature.oversized {
			if err := g.hit(e, "類似比較の文字数上限", e.signature.runes, s.Mode, s.WindowSeconds); err != nil {
				return err
			}
		}
	}
	if f.Mode != "off" {
		thread, subject, share := 1, 1, 1
		for _, old := range g.entries {
			if old.at <= e.at-domain.Time(f.WindowSeconds)*1e9 || old.cap && g.settings.ExemptCaps {
				continue
			}
			same := old.ip == e.ip && e.ip != (domain.Hash{}) || old.token == e.token && e.token != (domain.Hash{})
			if same {
				subject++
			}
			if e.thread != 0 && old.board == e.board && old.thread == e.thread {
				thread++
				if same {
					share++
				}
			}
		}
		reason, count := "", 0
		switch {
		case e.thread != 0 && thread > f.ThreadPosts:
			reason, count = "スレッドへの集中投稿", thread
		case subject > f.SubjectPosts:
			reason, count = "同一投稿者・接続元の連投", subject
		case e.thread != 0 && share >= f.ShareMinPosts && share*100 >= thread*f.SharePercent:
			reason, count = "スレッドの占有", share
		}
		if reason != "" {
			if err := g.hit(e, reason, count, f.Mode, f.WindowSeconds); err != nil {
				return err
			}
		}
	}
	if (s.Mode != "off" || f.Mode != "off") && (len(g.entries) >= guardHistoryLimit || e.at < g.overflowUntil) {
		// 履歴不足は攻撃の証拠にしない。保持済み履歴による拒否判定は上で継続する。
		return g.hit(e, "検出履歴の容量上限", guardHistoryLimit, "observe", guardHistorySeconds)
	}
	return nil
}

// hit は最大100件の管理用記録と、既存の429/Retry-After応答に接続する拒否を作る。
func (g *abuseGuard) hit(e guardEntry, reason string, count int, mode string, seconds int) error {
	g.events = append(g.events, GuardEvent{time.Unix(0, int64(e.at)).UTC().Format(time.RFC3339Nano), e.board, e.thread, e.number, reason, count, mode == "reject"})
	if len(g.events) > 100 {
		copy(g.events, g.events[len(g.events)-100:])
		g.events = g.events[:100]
	}
	if mode == "reject" {
		return fmt.Errorf("%w: %w", ErrAbuseGuard, &abuse.RateLimited{RetryAfter: uint64(seconds)})
	}
	return nil
}

// remember は失敗投稿を数えず、容量超過時も上限内で最新履歴へ置き換える。
func (g *abuseGuard) remember(e guardEntry) {
	if len(g.entries) >= guardHistoryLimit {
		// 最古の確定履歴を置き換える。失われた実投稿の期限を観測用に記録し、
		// 未確定候補も索引へ残して並列上限と取消を維持する。
		for i, old := range g.entries {
			if old.pending {
				continue
			}
			g.overflowUntil = max(g.overflowUntil, old.at+guardHistorySeconds*1e9)
			copy(g.entries[i:], g.entries[i+1:])
			g.entries[len(g.entries)-1] = guardEntry{}
			g.entries = g.entries[:len(g.entries)-1]
			break
		}
	}
	g.entries = append(g.entries, e)
	if !e.pending {
		g.trimSignatures()
	}
}

// settle は一括保存の取消時に候補を除き、確定時だけ番号を保持する。
func (g *abuseGuard) settle(id domain.ID, durable bool) {
	for i := range g.entries {
		if g.entries[i].id == id {
			if durable {
				g.entries[i].pending = false
				g.trimSignatures()
			} else {
				copy(g.entries[i:], g.entries[i+1:])
				g.entries[len(g.entries)-1] = guardEntry{}
				g.entries = g.entries[:len(g.entries)-1]
			}
			return
		}
	}
}
