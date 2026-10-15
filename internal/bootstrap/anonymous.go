// 匿名Cookieの発行をSync後に許可する。Cookie署名やID原文を保存・管理出力へ渡さない。
package bootstrap

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

type anonymousState struct {
	policy  AnonymousPolicy
	key     domain.Hash
	revoked map[domain.Hash]tokenRevocation
}

func (a *anonymousState) subject(id domain.ID) domain.Hash {
	return identity.MAC(a.key[:], "oimo/anon-subject/v1", id[:])
}
func (a *anonymousState) verify(raw string, now time.Time) (abuse.Anon, error) {
	token, e := abuse.VerifyAnon(raw, a.key[:], 4, now, uint64(a.policy.Generation))
	if e != nil {
		return token, e
	}
	if _, ok := a.revoked[a.subject(token.ID)]; ok {
		return abuse.Anon{}, abuse.ErrToken
	}
	return token, nil
}
func (r *Repository) loadAnonymous() error {
	row, ok := r.site.State().Rows["anon_policy:active"]
	if !ok {
		return nil
	}
	p, e := decodeAnonymous(row.Value)
	if e != nil {
		return e
	}
	if r.admission == nil || p.Enabled < r.admission.policy.Enabled || p.Enabled > domain.Time(time.Now().UnixNano()) {
		return errors.New("anonymous activation boundary mismatch")
	}
	for _, rule := range r.admission.policy.Rules {
		if rule.ID == p.ReplyRule || rule.ID == p.CreateRule {
			return errors.New("anonymous rule ID collision")
		}
	}
	master, e := readPrivate(filepath.Join(r.cfg.DataDir, "keys", "master-000001.key"), 32)
	if e != nil {
		return e
	}
	defer clear(master)
	key, e := identity.DeriveKey(master, "anon", 4)
	if e != nil {
		return e
	}
	a := &anonymousState{policy: p, key: key, revoked: map[domain.Hash]tokenRevocation{}}
	for name, row := range r.site.State().Rows {
		if strings.HasPrefix(name, "token_reissue:") {
			var counter tokenReissue
			if err := strictjson.Decode(row.Value, &counter); err != nil {
				return err
			}
			if counter.Updated < p.Enabled || counter.Updated > domain.Time(time.Now().UnixNano()) {
				return abuse.ErrRateClock
			}
		}
		if strings.HasPrefix(name, "token_issue:") {
			var issue tokenIssue
			if e = strictjson.Decode(row.Value, &issue); e != nil {
				return e
			}
			if issue.Issued < p.Enabled || issue.Issued > domain.Time(time.Now().UnixNano()) {
				return abuse.ErrRateClock
			}
		}
		if strings.HasPrefix(name, "token_revocation:") {
			var v tokenRevocation
			if e = strictjson.Decode(row.Value, &v); e != nil {
				return e
			}
			a.revoked[v.Subject] = v
		}
	}
	r.anonymous = a
	r.liveAnonymous.Store(a)
	r.admission.anonymous = &p
	return nil
}

// stopForAnonymousChange は管理処理の境界より後に旧設定で投稿させない。
func (r *Repository) stopForAnonymousChange() error {
	r.stopped = true
	for _, b := range r.posting {
		if _, e := b.worker.Submit(context.Background(), func() (any, error) { b.stopped = true; return nil, nil }); e != nil {
			return e
		}
	}
	return nil
}

// EnableAnonymous は投稿規制が有効な停止中サイトで一度だけ有効化する。再実行では世代を変えない。
func (r *Repository) EnableAnonymous(mode string) (AnonymousPolicy, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return AnonymousPolicy{}, e
	}
	if r.captureValidator == nil || r.admission == nil {
		return AnonymousPolicy{}, errors.New("enable posting admission first")
	}
	if mode != "required" {
		return AnonymousPolicy{}, errors.New("anonymous mode must be required")
	}
	if r.anonymous != nil {
		if mode != r.anonymous.policy.Mode {
			return AnonymousPolicy{}, errors.New("anonymous mode is immutable")
		}
		return r.anonymous.policy, nil
	}
	if e := r.stopForAnonymousChange(); e != nil {
		return AnonymousPolicy{}, e
	}
	now := time.Now()
	rows, e := r.rateHistory()
	if e != nil {
		return AnonymousPolicy{}, e
	}
	for _, row := range rows {
		if row.record.At >= domain.Time(now.UnixNano()) {
			return AnonymousPolicy{}, abuse.ErrRateClock
		}
	}
	p := AnonymousPolicy{Schema: "anon-policy-v4", Mode: mode, Modes: []anonymousModeBoundary{}, Enabled: domain.Time(now.UnixNano()), Generation: 1, KeyID: 4, ReplyRule: domain.NewID(), CreateRule: domain.NewID()}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return p, e
	}
	site.MinimumReader = max(site.MinimumReader, 70)
	e = appendControl(r.site, "anonymous_enable", []store.Mutation{mutation("site", "state", site, nil), mutation("anon_policy", "active", p, nil)}, []string{site.ID.String()})
	return p, e
}

// RevokeAnonymous は用途別HMACで一個を失効させる。nilは全体世代を上げる。停止中の管理CLI専用。
func (r *Repository) RevokeAnonymous(subject *domain.Hash) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if r.anonymous == nil {
		return errors.New("anonymous cookies are disabled")
	}
	if e := r.stopForAnonymousChange(); e != nil {
		return e
	}
	p := r.anonymous.policy
	if subject == nil {
		if p.Generation == ^domain.U64(0) {
			return errors.New("token generations exhausted")
		}
		p.Generation++
		return appendControl(r.site, "anonymous_revoke_all", []store.Mutation{mutation("anon_policy", "active", p, nil)}, []string{})
	}
	if *subject == (domain.Hash{}) {
		return abuse.ErrToken
	}
	if _, exists := r.anonymous.revoked[*subject]; exists {
		return nil
	}
	now := domain.Time(time.Now().UnixNano())
	v := tokenRevocation{ID: domain.NewID(), Subject: *subject, KeyID: 4, Generation: p.Generation, Revoked: now, Expires: now + 31*86400e9, Reason: "local_admin"}
	return appendControl(r.site, "anonymous_revoke", []store.Mutation{mutation("token_revocation", subject.String(), v, nil)}, []string{v.ID.String()})
}

// anonymousCookie は確認応答/期限更新の一時Cookie。新規発行だけIP/network履歴をSyncする。
// 板ワーカーから呼ばず、投稿処理の前後にサイトmutex下で呼ぶ。
func (r *Repository) anonymousCookie(raw string, ip netip.Addr, clock func() time.Time) (*http.Cookie, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return nil, e
	}
	now := clock()
	if now.UnixNano() < r.controlExpiryFloor.Load() {
		return nil, ErrControlExpiryClock
	}
	a := r.anonymous
	if a == nil {
		return nil, nil
	}
	token, e := a.verify(raw, now)
	if e == nil && token.Expires-now.Unix() > 7*86400 {
		return nil, nil
	}
	if e != nil {
		ready, err := r.recordTokenIssue(ip, now)
		if err != nil {
			return nil, err
		}
		token = abuse.Anon{ID: domain.NewID(), Generation: uint64(a.policy.Generation), ReadyAt: ready}
	} else {
		// 正常な期限更新は同じIDを維持し、満了済みの待機期限を引き継がない。
		if token.ReadyAt <= now.Unix() {
			token.ReadyAt = 0
		}
	}
	token.Issued = now.Unix()
	token.Expires = now.Unix() + 30*86400
	signed, e := abuse.IssueAnon(token, a.key[:], 4)
	if e != nil {
		return nil, e
	}
	base, _ := parseOrigin(r.cfg.Public.BaseURL)
	return &http.Cookie{Name: "oimo_anon", Value: signed, Path: "/", HttpOnly: true, Secure: base.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: 30 * 86400, Expires: time.Unix(token.Expires, 0)}, nil
}

// recordTokenIssue は発行上限・同じIP/確認済みホストの再発行を検査し、同期後に待機期限を返す。
// DNSは呼ばず、所有者mutex下で既存cacheを参照する。ホスト未確認ではIP単位で数える。
func (r *Repository) recordTokenIssue(ip netip.Addr, now time.Time) (int64, error) {
	ip = ip.Unmap()
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	h := identity.MAC(r.admission.secret[:], "oimo/token-issue/ip/v1", []byte(ip.String()))
	network := identity.MAC(r.admission.secret[:], "oimo/token-issue/network/v1", []byte(netip.PrefixFrom(ip, bits).Masked().String()))
	at := domain.Time(now.UnixNano())
	if !ip.IsValid() || at < r.anonymous.policy.Enabled {
		return 0, abuse.ErrRateClock
	}
	pair := r.tokenReissueOrigin(ip)
	networkExp := []domain.Time{}
	total := 0
	for name, row := range r.site.State().Rows {
		if !strings.HasPrefix(name, "token_issue:") {
			continue
		}
		total++
		var v tokenIssue
		if e := strictjson.Decode(row.Value, &v); e != nil {
			return 0, e
		}
		if v.Issued > at {
			return 0, abuse.ErrRateClock
		}
		if v.Expires <= at {
			continue
		}
		if v.Network == network {
			networkExp = append(networkExp, v.Expires)
		}

	}
	// 期限順の必要な回収時刻を返す。記録を忘れて新しいCookieを発行しない。
	wait := tokenIssueWait(at, networkExp, 50)
	if wait > 0 {
		return 0, &abuse.RateLimited{RetryAfter: wait}
	}
	if total >= 200000 {
		return 0, abuse.ErrRateCapacity
	}
	counter, ready, err := r.nextTokenReissue(pair, at)
	if err != nil {
		return 0, err
	}
	v := tokenIssue{ID: domain.NewID(), Subject: h, Network: network, KeyID: 7, Issued: at, Expires: at + 3660e9}
	changes := []store.Mutation{}
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return 0, err
	}
	if site.MinimumReader < 65 {
		site.MinimumReader = 65
		changes = append(changes, mutation("site", "state", site, nil))
	}
	changes = append(changes, mutation("token_reissue", pair.String(), counter, nil))
	changes = append(changes, mutation("token_issue", v.ID.String(), v, nil))
	if e := appendControl(r.site, "anonymous_issue", changes, []string{v.ID.String()}); e != nil {
		r.stopped = true
		return 0, e
	}
	return ready, nil
}
func tokenIssueWait(at domain.Time, expires []domain.Time, limit int) uint64 {
	if len(expires) < limit {
		return 0
	}
	// 同じ主体の発行は最大50件。小さな入力だけを整列する。
	slices.Sort(expires)
	delta := uint64(expires[len(expires)-limit] - at)
	return (delta + 999999999) / 1000000000
}

// anonymousRequestCookie は機能無効時には匿名Cookieを認証材料として扱わない。
func (r *Repository) anonymousRequestCookie(h http.Header) (string, error) {
	r.mu.Lock()
	enabled := r.anonymous != nil
	r.mu.Unlock()
	if !enabled {
		return "", nil
	}
	return singlePostingCookie(h, "oimo_anon", 256)
}
