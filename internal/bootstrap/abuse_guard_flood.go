// 連投件数を有界の期限列と主体索引で数え、所有列での全履歴走査を避ける。
package bootstrap

import (
	"oimobbs/internal/domain"
	"sort"
)

type guardFloodThread struct {
	board  domain.ID
	thread uint64
}
type guardFloodPair struct{ ip, token domain.Hash }
type guardFloodCounts struct {
	total       int
	ips, tokens map[domain.Hash]int
	pairs       map[guardFloodPair]int
}
type guardFloodRow struct {
	at     domain.Time
	thread guardFloodThread
	pair   guardFloodPair
	active bool
}
type guardFloodIndex struct {
	window   int
	exempt   bool
	global   guardFloodCounts
	threads  map[guardFloodThread]*guardFloodCounts
	rows     []*guardFloodRow
	head     int
	lastTime domain.Time
}

// floodCounts は履歴と同じ厳密な期限・IPまたはtokenの和集合で現在候補を含めて数える。
// 設定変更時に再構築し、確定・取消・削除・容量置換の更新は同じguard mutex内で行う。
func (g *abuseGuard) floodCounts(e guardEntry) (thread, subject, share int) {
	f := g.flood
	if f == nil || f.window != g.settings.Flood.WindowSeconds || f.exempt != g.settings.ExemptCaps {
		f = &guardFloodIndex{window: g.settings.Flood.WindowSeconds, exempt: g.settings.ExemptCaps, threads: map[guardFloodThread]*guardFloodCounts{}, rows: make([]*guardFloodRow, 0, guardHistoryLimit*2)}
		g.flood = f
		for i := range g.entries {
			f.add(&g.entries[i])
		}
		sort.Slice(f.rows, func(i, j int) bool { return f.rows[i].at < f.rows[j].at })
	}
	f.expire(e.at - domain.Time(f.window)*1e9)
	thread, subject, share = 1, 1+f.global.subject(e.ip, e.token), 1
	if e.thread != 0 {
		if counts := f.threads[guardFloodThread{e.board, e.thread}]; counts != nil {
			thread += counts.total
			share += counts.subject(e.ip, e.token)
		}
	}
	return
}

func (c *guardFloodCounts) subject(ip, token domain.Hash) int {
	n := 0
	if ip != (domain.Hash{}) {
		n += c.ips[ip]
	}
	if token != (domain.Hash{}) {
		n += c.tokens[token]
	}
	if ip != (domain.Hash{}) && token != (domain.Hash{}) {
		n -= c.pairs[guardFloodPair{ip, token}]
	}
	return n
}

// add は検査後の履歴だけを索引へ加える。古い時刻の直接挿入は呼出元で再構築へ戻す。
func (f *guardFloodIndex) add(e *guardEntry) {
	e.flood = nil
	f.lastTime = max(f.lastTime, e.at)
	if e.cap && f.exempt {
		return
	}
	row := &guardFloodRow{at: e.at, thread: guardFloodThread{e.board, e.thread}, pair: guardFloodPair{e.ip, e.token}, active: true}
	e.flood = row
	f.rows = append(f.rows, row)
	f.global.change(row.pair, 1)
	c := f.threads[row.thread]
	if c == nil {
		c = &guardFloodCounts{}
		f.threads[row.thread] = c
	}
	c.change(row.pair, 1)
}

// change はゼロ件のキーを即座に消し、履歴件数を超えて主体識別子を保持しない。
func (c *guardFloodCounts) change(pair guardFloodPair, delta int) {
	c.total += delta
	if delta > 0 && c.ips == nil {
		c.ips = map[domain.Hash]int{}
		c.tokens = map[domain.Hash]int{}
		c.pairs = map[guardFloodPair]int{}
	}
	if pair.ip != (domain.Hash{}) {
		guardFloodChange(c.ips, pair.ip, delta)
	}
	if pair.token != (domain.Hash{}) {
		guardFloodChange(c.tokens, pair.token, delta)
	}
	if pair.ip != (domain.Hash{}) && pair.token != (domain.Hash{}) {
		guardFloodChange(c.pairs, pair, delta)
	}
}
func guardFloodChange[K comparable](counts map[K]int, key K, delta int) {
	if n := counts[key] + delta; n == 0 {
		delete(counts, key)
	} else {
		counts[key] = n
	}
}

// remove は期限列へ残る無効cellも一度だけ減算する。取消と期限切れが重なっても二重に引かない。
func (f *guardFloodIndex) remove(row *guardFloodRow) {
	if row == nil || !row.active {
		return
	}
	row.active = false
	f.global.change(row.pair, -1)
	c := f.threads[row.thread]
	c.change(row.pair, -1)
	if c.total == 0 {
		delete(f.threads, row.thread)
	}
}
func (f *guardFloodIndex) expire(cutoff domain.Time) {
	for f.head < len(f.rows) && f.rows[f.head].at <= cutoff {
		f.remove(f.rows[f.head])
		f.rows[f.head] = nil
		f.head++
	}
	f.compact()
}

// compact は取消済みcellを除き、期限列の参照数と背後配列を最大履歴の二倍へ制限する。
func (f *guardFloodIndex) compact() {
	if len(f.rows) < guardHistoryLimit*2 {
		return
	}
	rows := make([]*guardFloodRow, 0, guardHistoryLimit*2)
	for _, row := range f.rows[f.head:] {
		if row.active {
			rows = append(rows, row)
		}
	}
	f.rows, f.head = rows, 0
}
