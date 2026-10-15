// 本文を読む前の試行制限。直接接続のpeerだけを使い、転送ヘッダーは信用しない。
package bootstrap

import (
	"errors"
	"net"
	"net/http"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/identity"
	"strconv"
	"time"
)

func (a *admission) attempt(remote string, clock func() time.Time) error {
	host, _, e := net.SplitHostPort(remote)
	if e != nil {
		return ErrPostingRequest
	}
	ip, e := parseRateIP(host)
	if e != nil {
		return ErrPostingRequest
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := clock()
	if now.UnixNano() < int64(max(a.policy.Enabled, a.lastAttempt)) {
		return abuse.ErrRateClock
	}
	if a.lastPrune.IsZero() || now.Sub(a.lastPrune) >= time.Minute {
		a.limits.Prune(now)
		a.pruneBoardKeys()
		a.lastPrune = now
	}
	a.lastAttempt = domain.Time(now.UnixNano())
	h := identity.MAC(a.secret[:], "oimo/attempt/v1", []byte(ip.String()))
	ticket, e := a.limits.Reserve(now, []abuse.RateCharge{{Key: h.String(), Spec: abuse.RateSpec{Tokens: 10, Every: time.Second, Burst: 20}, Cost: 1}})
	if e != nil {
		return e
	}
	return a.limits.Commit(ticket)
}

// admitAttempt は公開POSTにのみ適用し、拒否時は本文を読み取らない。
func (repo *Repository) admitAttempt(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" || r.URL.Path != "/test/bbs.cgi" && r.URL.Path != "/web/post" {
		return true
	}
	repo.mu.Lock()
	a := repo.admission
	repo.mu.Unlock()
	if a == nil {
		return true
	}
	e := a.attempt(evidence.ClientRemoteAddr(r), time.Now)
	if e == nil {
		return true
	}
	status, message := 503, "現在投稿を利用できません。"
	var limited *abuse.RateLimited
	if errors.As(e, &limited) {
		status, message = 429, "投稿間隔を空けて再送してください。"
		w.Header().Set("Retry-After", strconv.FormatUint(limited.RetryAfter, 10))
	}
	if r.URL.Path == "/test/bbs.cgi" {
		writeLegacyResult(w, r, status, "error", message, "")
	} else {
		writePostingPage(w, status, postingPage{Heading: message, Message: "元の画面に戻って入力内容を確認してください。"})
	}
	return false
}
