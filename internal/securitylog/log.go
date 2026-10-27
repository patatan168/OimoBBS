// Package securitylog は7日間の検出・拒否を時間別に集約し、再起動後も管理画面へ返す。
package securitylog

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxSamples = 256
const retention = 7 * 24 * time.Hour

// Event は秘密や接続元を含まない検出材料。BodyとMatchBodyは管理者向けの抜粋。
type Event struct {
	Operation      string    `json:"operation"`
	MatchOperation string    `json:"match_operation"`
	At             time.Time `json:"at"`
	Source         string    `json:"source"`
	Reason         string    `json:"reason"`
	Rejected       bool      `json:"rejected"`
	Dummy          bool      `json:"dummy"` // 保存済みの確認用ログを実データから除外するために保持する。
	Board          string    `json:"board"`
	Thread         uint64    `json:"thread"`
	Post           uint32    `json:"post"`
	Path           string    `json:"path"`
	Body           string    `json:"body"`
	MatchBody      string    `json:"match_body"`
	MatchBoard     string    `json:"match_board"`
	MatchThread    uint64    `json:"match_thread"`
	MatchPost      uint32    `json:"match_post"`
}

// Row は同じ時間帯・理由・内容の発生回数と、最初・最後の発生日時。
type Row struct {
	ID string `json:"id,omitempty"`
	Event
	First   time.Time `json:"first"`
	Count   uint64    `json:"count"`
	Limited bool      `json:"limited"`
}

// ReasonCount は実データだけの理由別集計。ダミーを運用上の件数へ加算しない。
type ReasonCount struct {
	Source             string
	Reason             string
	Detected, Rejected uint64
}

// View は7日分の集計と新しい順の本文例。Rowsは画面用に1ページ50組。
type View struct {
	Rows                        []Row
	Reasons                     []ReasonCount
	Detected, Rejected, Limited uint64
	Error                       string
	Groups                      int
	Page                        int
}

type message struct {
	event   *Event
	barrier chan error
	stop    bool
}

// Log は固定長の待機列と単一writerで時間別ファイルを更新する。
type Log struct {
	dir      string
	queue    chan message
	mu       sync.Mutex
	closed   bool
	done     chan struct{}
	err      error
	overflow map[string]Row
}

// Open は保存先を作り、書込み所有goroutineを起動する。既存ログはView時に読み込む。
func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	l := &Log{dir: dir, queue: make(chan message, 256), done: make(chan struct{}), overflow: map[string]Row{}}
	if err := l.prune(time.Now()); err != nil {
		return nil, err
	}
	go l.run()
	return l, nil
}

// Excerpt はUTF-8の文字境界を保ち、本文例を最大1024文字へ制限する。
func Excerpt(s string) string {
	count := 0
	for i := range s {
		if count == 1024 {
			return strings.Clone(s[:i]) + "…"
		}
		count++
	}
	return strings.Clone(s)
}

// Add は保存I/Oを待たず追加する。待機列が満杯なら本文例を省略し、理由別件数をまとめる。
func (l *Log) Add(e Event) {
	if l == nil {
		return
	}
	e.At = e.At.UTC()
	e.Body = Excerpt(e.Body)
	e.MatchBody = Excerpt(e.MatchBody)
	e.Path = Excerpt(e.Path)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	select {
	case l.queue <- message{event: &e}:
		return
	default:
	}
	e = withoutSample(e)
	key := bucket(e) + overflowKey(e)
	row, ok := l.overflow[key]
	if !ok {
		row = Row{Event: e, First: e.At, Limited: true}
	}
	row.Count++
	if e.At.Before(row.First) {
		row.First = e.At
	}
	if !e.At.Before(row.At) {
		row.Event = e
	}
	l.overflow[key] = row
}

// Close は待機中の全件をSyncしてwriterを終了する。複数回呼び出せる。
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	first := !l.closed
	l.closed = true
	l.mu.Unlock()
	if first {
		select {
		case l.queue <- message{stop: true}:
		case <-l.done:
		}
	}
	<-l.done
	return l.err
}

// flush は表示前の保存完了を待つ。Closeと競合しても終了通知で待機を解く。
func (l *Log) flush() error {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		<-l.done
		return l.err
	}
	done := make(chan error, 1)
	select {
	case l.queue <- message{barrier: done}:
	case <-l.done:
		return l.err
	}
	select {
	case err := <-done:
		return err
	case <-l.done:
		return l.err
	}
}

func bucket(e Event) string { return e.At.UTC().Format("20060102T15") }
func fingerprint(e Event) string {
	// 時刻・レス番号は同じ内容の件数集約を分断しない。
	raw, _ := json.Marshal([]any{e.Source, e.Reason, e.Rejected, e.Dummy, e.Board, e.Thread, e.Path, e.Body, e.MatchBody})
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func load(path string) (map[string]Row, error) {
	rows := map[string]Row{}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return rows, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBucketBytes {
		return nil, errors.New("security log file too large")
	}
	if err = json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

// save は一時ファイルのSync、rename、directory Syncで中断時に旧版または新版を保持する。
func save(path string, rows map[string]Row) error {
	_, err := saveSnapshot(path, rows)
	return err
}

// saveSnapshot は保存したtemp file自体のidentityも返す。rename後に別fileを記録しない。
// identity取得だけの失敗は再利用を止め、保存・同期の成否を変えない。
func saveSnapshot(path string, rows map[string]Row) (os.FileInfo, error) {
	raw, err := json.Marshal(rows)
	if err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	var info os.FileInfo
	if err == nil {
		info, _ = f.Stat()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return nil, err
	}
	if err = os.Rename(name, path); err != nil {
		return nil, err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err = errors.Join(d.Sync(), d.Close()); err != nil {
		return nil, err
	}
	return info, nil
}

func overflowKey(e Event) string {
	return fmt.Sprintf("overflow:%s:%s:%t:%t", e.Source, e.Reason, e.Rejected, e.Dummy)
}
func withoutSample(e Event) Event {
	e.Body = ""
	e.MatchBody = ""
	e.Path = ""
	e.Board = ""
	e.Thread = 0
	e.Post = 0
	e.MatchBoard = ""
	e.MatchThread = 0
	e.MatchPost = 0
	e.Operation = ""
	e.MatchOperation = ""
	return e
}
func merge(rows map[string]Row, e Event) { mergeCount(rows, Row{Event: e, First: e.At, Count: 1}) }
func mergeCount(rows map[string]Row, in Row) {
	e := in.Event
	key := fingerprint(e)
	row, ok := rows[key]
	if in.Limited || !ok && len(rows) >= maxSamples {
		key = overflowKey(e)
		row, ok = rows[key]
		e = withoutSample(e)
		in.Limited = true
	}
	if !ok {
		row = Row{Event: e, First: in.First, Limited: in.Limited}
	}
	row.Count += in.Count
	if in.First.Before(row.First) {
		row.First = in.First
	}
	if !e.At.Before(row.At) {
		row.Event = e
	}
	rows[key] = row
}

func (l *Log) run() {
	defer close(l.done)
	var cache bucketRows
	for {
		first := <-l.queue
		batch := []message{first}
		for len(batch) < 256 {
			select {
			case m := <-l.queue:
				batch = append(batch, m)
			default:
				goto drained
			}
		}
	drained:
		l.mu.Lock()
		overflow := l.overflow
		l.overflow = map[string]Row{}
		l.mu.Unlock()
		changed := map[string]map[string]Row{}
		stop := false
		for _, m := range batch {
			if m.stop {
				stop = true
			}
			if m.event == nil {
				continue
			}
			e := *m.event
			if e.At.Before(time.Now().Add(-retention)) {
				continue
			}
			name := bucket(e)
			rows, ok := changed[name]
			if !ok {
				var err error
				rows, err = cache.load(l.dir, name)
				if err != nil {
					l.err = err
					continue
				}
				changed[name] = rows
			}
			merge(rows, e)
		}
		for _, row := range overflow {
			if row.At.Before(time.Now().Add(-retention)) {
				continue
			}
			name := bucket(row.Event)
			rows, ok := changed[name]
			if !ok {
				var err error
				rows, err = cache.load(l.dir, name)
				if err != nil {
					l.err = err
					continue
				}
				changed[name] = rows
			}
			mergeCount(rows, row)
		}
		// 再利用mapは更新済みなので、保存失敗で未保存状態を持ち越さない。
		if len(changed) > 0 {
			cache.clear()
		}
		for name, rows := range changed {
			info, err := saveSnapshot(filepath.Join(l.dir, name+".json"), rows)
			if err != nil {
				l.err = err
			} else {
				cache.remember(name, rows, info)
			}
		}
		if err := l.prune(time.Now()); err != nil {
			l.err = err
		}
		cache.expire(time.Now())
		for _, m := range batch {
			if m.barrier != nil {
				m.barrier <- l.err
			}
		}
		if stop {
			return
		}
	}
}

// prune は保存時間帯の末尾が7日前に達したファイルだけを削除する。
func (l *Log) prune(now time.Time) error {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		at, err := time.Parse("20060102T15.json", e.Name())
		if err != nil {
			continue
		}
		if !at.Add(time.Hour).After(now.Add(-retention)) {
			if err = os.Remove(filepath.Join(l.dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// View は実データの全件数と新しい本文例50組を返す。保持上限と保存エラーも返す。
func (l *Log) View(now time.Time) (View, error) { return l.Filtered(now, Filter{}) }

// Filter は一覧の種類・結果・理由とページ番号。集計は常に7日分を返す。
type Filter struct {
	Source, Result, Reason string
	Page                   int
}

// Filtered は絞込みを全保存行へ適用した後、新しい順に最大50組を返す。
func (l *Log) Filtered(now time.Time, filter Filter) (View, error) {
	if filter.Page < 1 {
		filter.Page = 1
	}
	if filter.Page > 10000 {
		filter.Page = 10000
	}
	limit := filter.Page * 50

	v := View{Rows: []Row{}, Reasons: []ReasonCount{}, Page: filter.Page}
	if err := l.flush(); err != nil {
		v.Error = err.Error()
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return v, err
	}
	counts := map[string]ReasonCount{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		at, err := time.Parse("20060102T15.json", entry.Name())
		if err != nil || !at.Add(time.Hour).After(now.Add(-retention)) {
			continue
		}
		rows, err := load(filepath.Join(l.dir, entry.Name()))
		if err != nil {
			return v, err
		}
		for key, row := range rows {
			row.ID = strings.TrimSuffix(entry.Name(), ".json") + ":" + key
			if row.Dummy || row.At.Before(now.Add(-retention)) {
				continue
			}
			key := row.Source + "\x00" + row.Reason
			c := counts[key]
			c.Source = row.Source
			c.Reason = row.Reason
			if row.Rejected {
				v.Rejected += row.Count
				c.Rejected += row.Count
			} else {
				v.Detected += row.Count
				c.Detected += row.Count
			}
			counts[key] = c
			if row.Limited {
				v.Limited += row.Count
			}
			if filter.Source != "" && row.Source != filter.Source || filter.Result == "rejected" && !row.Rejected || filter.Result == "detected" && row.Rejected || filter.Reason != "" && row.Reason != filter.Reason {
				continue
			}
			v.Groups++
			v.Rows = append(v.Rows, row)
		}
		sortRows(v.Rows)
		if len(v.Rows) > limit {
			v.Rows = v.Rows[:limit]
		}
	}
	offset := (filter.Page - 1) * 50
	if offset >= len(v.Rows) {
		v.Rows = []Row{}
	} else {
		v.Rows = v.Rows[offset:]
	}
	for _, c := range counts {
		v.Reasons = append(v.Reasons, c)
	}
	sort.Slice(v.Reasons, func(i, j int) bool {
		a, b := v.Reasons[i], v.Reasons[j]
		if a.Source == b.Source {
			return a.Reason < b.Reason
		}
		return a.Source < b.Source
	})
	return v, nil
}
func sortRows(rows []Row) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].At.Equal(rows[j].At) {
			return fingerprint(rows[i].Event) < fingerprint(rows[j].Event)
		}
		return rows[i].At.After(rows[j].At)
	})
}

// Find は保存済みの単一本文例をIDで取得する。IDをファイルパスとして直接使用しない。
func (l *Log) Find(id string, now time.Time) (Row, error) {
	var row Row
	parts := strings.Split(id, ":")
	if len(parts) != 2 || len(parts[1]) != 64 {
		return row, os.ErrNotExist
	}
	hour, err := time.Parse("20060102T15", parts[0])
	if err != nil || hour.After(now) || !hour.Add(time.Hour).After(now.Add(-retention)) {
		return row, os.ErrNotExist
	}
	for _, c := range parts[1] {
		if !(c >= 'a' && c <= 'f' || c >= '0' && c <= '9') {
			return row, os.ErrNotExist
		}
	}
	if err = l.flush(); err != nil {
		return row, err
	}
	rows, err := load(filepath.Join(l.dir, hour.Format("20060102T15")+".json"))
	if err != nil {
		return row, err
	}
	row, ok := rows[parts[1]]
	if !ok || row.Dummy || row.At.Before(now.Add(-retention)) {
		return Row{}, os.ErrNotExist
	}
	row.ID = id
	return row, nil
}
