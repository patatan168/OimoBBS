// 署名検証済みCookieの明確なフォーム違反だけを、有界メモリで自動的な一時停止へ接続する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/strictjson"
	"strconv"
	"strings"
	"sync"
	"time"
)

const botReader = 97
const botFailureLimit = 8
const botSubjectLimit = 4096
const botWindow = time.Minute
const botStop = 2 * time.Minute

// ErrBotGuard は反復したフォーム違反によるCookie単位の一時投稿停止。
var ErrBotGuard = errors.New("automated malformed posting stopped")

// BotStats はIP・Cookie・本文を含まないプロセス内集計。再起動で初期化する。
type BotStats struct {
	Subjects int    `json:"subjects"`
	Active   int    `json:"active"`
	Signals  uint64 `json:"signals"`
	Stops    uint64 `json:"stops"`
	Rejected uint64 `json:"rejected"`
	Overflow uint64 `json:"overflow"`
}

type botState struct {
	requests       [botFailureLimit]domain.Hash
	count          int
	started, until time.Time
	blocked        bool
}

type botGuard struct {
	mu        sync.Mutex
	mode      string
	states    map[domain.Hash]botState
	lastPrune time.Time
	totals    BotStats
}

// effectiveBotMode は旧保存値・未設定のサイトでも、明確な違反への自動停止を有効にする。
func effectiveBotMode(mode string) string {
	if mode == "" {
		return "reject"
	}
	return mode
}

// UnmarshalJSON は旧設定の署名対象を変えず、追加項目の省略だけを許す。
func (v *AbuseGuardSettings) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields["bot_mode"]; !ok {
		fields["bot_mode"] = json.RawMessage(`""`)
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	type plain AbuseGuardSettings
	var parsed plain
	if err := strictjson.Decode(normalized, &parsed); err != nil {
		return err
	}
	*v = AbuseGuardSettings(parsed)
	return nil
}

// configure はモードだけを切り替え、違反履歴と停止期限を維持する。
func (g *botGuard) configure(mode string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.mode = effectiveBotMode(mode)
}

// record は固定60秒窓の異なる違反だけを数える。停止中は記録も期限延長もしない。
// 満杯なら新規主体の追加だけを諦め、無関係な利用者は拒否しない。
func (g *botGuard) record(subject, request domain.Hash, now time.Time) {
	if subject == (domain.Hash{}) || request == (domain.Hash{}) {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.mode == "off" {
		return
	}
	if g.lastPrune.IsZero() || now.Sub(g.lastPrune) >= time.Minute {
		for key, state := range g.states {
			if !now.Before(state.until) {
				delete(g.states, key)
			}
		}
		g.lastPrune = now
	}
	state, exists := g.states[subject]
	if exists && now.Before(state.started) {
		return
	}
	if !exists || !now.Before(state.until) {
		if !exists && len(g.states) >= botSubjectLimit {
			g.totals.Overflow++
			return
		}
		state = botState{started: now, until: now.Add(botWindow)}
	}
	if state.blocked {
		return
	}
	for _, old := range state.requests[:state.count] {
		if old == request {
			return
		}
	}
	state.requests[state.count] = request
	state.count++
	g.totals.Signals++
	if state.count == botFailureLimit {
		state.blocked = true
		state.until = now.Add(botStop)
		g.totals.Stops++
	}
	if g.states == nil {
		g.states = make(map[domain.Hash]botState)
	}
	g.states[subject] = state
}

// check は新規投稿だけを停止し、期限を秒へ切り上げて既存の429応答へ接続する。
func (g *botGuard) check(subject domain.Hash, now time.Time) error {
	if subject == (domain.Hash{}) {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.mode == "off" || g.mode == "observe" {
		return nil
	}
	state := g.states[subject]
	if !state.blocked || !now.Before(state.until) {
		return nil
	}
	g.totals.Rejected++
	seconds := uint64((state.until.Sub(now) + time.Second - 1) / time.Second)
	return fmt.Errorf("%w: %w", ErrBotGuard, &abuse.RateLimited{RetryAfter: seconds})
}

// stats は最大4096主体の現在有効な窓と停止数を、管理要求時だけ数える。
func (g *botGuard) stats(now time.Time) BotStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := g.totals
	for _, state := range g.states {
		if now.Before(state.until) {
			v.Subjects++
			if state.blocked {
				v.Active++
			}
		}
	}
	return v
}

// recordBotFailure は既存の匿名資格を再検証し、IPや申告Cookie値で他人を停止させない。
// 同一本文の通信再送は同じHMACになり、違反件数を増やさない。
func (r *Repository) recordBotFailure(raw, reason, route string, body []byte, now time.Time) {
	a := r.liveAnonymous.Load()
	if a == nil || raw == "" {
		return
	}
	token, err := a.verify(raw, now)
	if err != nil {
		return
	}
	subject := a.subject(token.ID)
	request := identity.MAC(a.key[:], "oimo/bot-failure/v1", []byte(reason), []byte(route), body)
	r.bot.record(subject, request, trafficNow())
}

// malformedCSRF は構文が壊れた非空の値だけを違反候補にする。
// 期限切れ・別タブでのCookie交換・署名不一致だけではBotと判断しない。
func malformedCSRF(token string) bool {
	if token == "" {
		return false
	}
	if len(token) > 128 {
		return true
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != "6" || len(parts[3]) != 43 {
		return true
	}
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	return err != nil || issued < 0 || strconv.FormatInt(issued, 10) != parts[2]
}
