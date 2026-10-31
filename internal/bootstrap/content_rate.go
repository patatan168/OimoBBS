// 同一内容の投稿をIP・検証済みCookieごとの移動窓で制限し、保存結果に応じて予約を確定する。
package bootstrap

import (
	"container/heap"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"oimobbs/internal/abuse"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ErrSameContent は通常の投稿間隔と区別する同一内容の件数超過。
var ErrSameContent = errors.New("same content posting limit exceeded")

const contentRateReader = 106
const contentRateHistorySeconds = 600
const contentRateHistoryLimit = 65536

// ContentRateSettings は同一投稿先・正規化済み内容のIP枠とCookie枠。両方を満たす必要がある。
type ContentRateSettings struct {
	IPSeconds     int `json:"ip_seconds"`
	IPPosts       int `json:"ip_posts"`
	CookieSeconds int `json:"cookie_seconds"`
	CookiePosts   int `json:"cookie_posts"`
}

func defaultContentRateSettings() ContentRateSettings { return ContentRateSettings{60, 20, 60, 1} }
func (v ContentRateSettings) valid() bool {
	return v.IPSeconds >= 1 && v.IPSeconds <= contentRateHistorySeconds && v.CookieSeconds >= 1 && v.CookieSeconds <= contentRateHistorySeconds && v.IPPosts >= 1 && v.IPPosts <= 1000 && v.CookiePosts >= 1 && v.CookiePosts <= 1000
}

// contentRates は旧保存値や旧APIの省略を補完する。明示されたゼロ・範囲外はvalidで拒否する。
func (v OperationSettings) contentRates() ContentRateSettings {
	if v.ContentRates == nil {
		return defaultContentRateSettings()
	}
	return *v.ContentRates
}

// ensureContentRateFormat は新しい投稿索引を保存する前に旧バイナリによる読み込みを止める。
func (r *Repository) ensureContentRateFormat() error {
	if r.contentRateReady.Load() {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.available(); err != nil {
		return err
	}
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	if site.MinimumReader >= contentRateReader {
		r.contentRateReady.Store(true)
		return nil
	}
	site.MinimumReader = contentRateReader
	if err := appendControl(r.site, "content_rate_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{site.ID.String()}); err != nil {
		r.stopped = true
		return err
	}
	r.contentRateReady.Store(true)
	return nil
}

// contentIPSubject はIPv4射影を正規化し、IPv6もアドレス単位でHMAC化する。
func (b *postingBoard) contentIPSubject(raw string) domain.Hash {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return domain.Hash{}
	}
	return identity.MAC(b.dedupKey[:], "oimo/content-ip/v1", []byte(ip.Unmap().String()))
}

type contentRateKey struct {
	content, subject domain.Hash
	cookie           bool
}
type contentRateEntry struct {
	id    domain.ID
	at    domain.Time
	keys  []contentRateKey
	index int
}
type contentRateHeap []*contentRateEntry

func (h contentRateHeap) Len() int           { return len(h) }
func (h contentRateHeap) Less(i, j int) bool { return h[i].at < h[j].at }
func (h contentRateHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i]; h[i].index = i; h[j].index = j }
func (h *contentRateHeap) Push(v any) {
	e := v.(*contentRateEntry)
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *contentRateHeap) Pop() any {
	v := *h
	e := v[len(v)-1]
	e.index = -1
	v[len(v)-1] = nil
	*h = v[:len(v)-1]
	return e
}

// contentRateLimiter は本文を保持しない有界索引。所有するabuseGuardのmutexの下だけで使う。
// 未確定予約も数え、失敗分は取消し、起動時は照合済み投稿から再構築する。
type contentRateLimiter struct {
	entries       map[domain.ID]*contentRateEntry
	subjects      map[contentRateKey]map[domain.ID]*contentRateEntry
	expiry        contentRateHeap
	overflowUntil domain.Time
}

// contentKeys は内容HMACに接続元と検証済みCookieを別々に束縛する。
func contentKeys(e guardEntry) []contentRateKey {
	if e.content == (domain.Hash{}) {
		return nil
	}
	keys := make([]contentRateKey, 0, 2)
	if e.contentIP != (domain.Hash{}) {
		keys = append(keys, contentRateKey{e.content, e.contentIP, false})
	}
	if e.token != (domain.Hash{}) {
		keys = append(keys, contentRateKey{e.content, e.token, true})
	}
	return keys
}

// expire は最大設定期間を過ぎた確定履歴を主体索引からも解放する。
func (l *contentRateLimiter) expire(now domain.Time) {
	for len(l.expiry) > 0 && l.expiry[0].at <= now-contentRateHistorySeconds*1e9 {
		e := heap.Pop(&l.expiry).(*contentRateEntry)
		l.remove(e.id)
	}
}

// remove は保存失敗の予約と期限切れ履歴を全索引から除く。
func (l *contentRateLimiter) remove(id domain.ID) {
	e := l.entries[id]
	if e == nil {
		return
	}
	if e.index >= 0 {
		heap.Remove(&l.expiry, e.index)
	}
	for _, key := range e.keys {
		delete(l.subjects[key], id)
		if len(l.subjects[key]) == 0 {
			delete(l.subjects, key)
		}
	}
	delete(l.entries, id)
}

// remember は復旧と予約で共用する。容量を超えた復旧履歴の有効期間には新規受付を止める。
func (l *contentRateLimiter) remember(e guardEntry) {
	keys := contentKeys(e)
	if len(keys) == 0 {
		return
	}
	if len(l.entries) >= contentRateHistoryLimit {
		l.overflowUntil = max(l.overflowUntil, e.at+contentRateHistorySeconds*1e9)
		return
	}
	if l.entries == nil {
		l.entries = map[domain.ID]*contentRateEntry{}
		l.subjects = map[contentRateKey]map[domain.ID]*contentRateEntry{}
	}
	if l.entries[e.id] != nil {
		return
	}
	entry := &contentRateEntry{id: e.id, at: e.at, keys: keys, index: -1}
	l.entries[e.id] = entry
	for _, key := range keys {
		if l.subjects[key] == nil {
			l.subjects[key] = map[domain.ID]*contentRateEntry{}
		}
		l.subjects[key][e.id] = entry
	}
	heap.Push(&l.expiry, entry)
}

// reserve は固定の時計区切りでなく直近の移動窓を使い、両枠を検査してから一括予約する。
func (l *contentRateLimiter) reserve(e guardEntry, v ContentRateSettings) error {
	keys := contentKeys(e)
	if len(keys) == 0 {
		return nil
	}
	l.expire(e.at)
	if e.at < l.overflowUntil || len(l.entries) >= contentRateHistoryLimit || len(l.expiry) >= contentRateHistoryLimit {
		return errPostingMemory
	}
	var retry domain.Time
	for _, key := range keys {
		seconds, limit := v.IPSeconds, v.IPPosts
		if key.cookie {
			seconds, limit = v.CookieSeconds, v.CookiePosts
		}
		cutoff := e.at - domain.Time(seconds)*1e9
		times := make([]domain.Time, 0, len(l.subjects[key]))
		for _, old := range l.subjects[key] {
			if old.at > cutoff {
				times = append(times, old.at)
			}
		}
		if len(times) >= limit {
			slices.Sort(times)
			retry = max(retry, times[len(times)-limit]+domain.Time(seconds)*1e9-e.at)
		}
	}
	if retry > 0 {
		return fmt.Errorf("%w: %w", ErrSameContent, &abuse.RateLimited{RetryAfter: uint64((retry + domain.Time(time.Second) - 1) / domain.Time(time.Second))})
	}
	l.remember(e)
	return nil
}
