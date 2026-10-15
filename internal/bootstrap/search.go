// 公開タイトルのメモリ要約を検索し、送信リースで削除・期限との競合を拒否する。
package bootstrap

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
)

type titleQuery struct {
	Terms        []string
	Board, State string
	Order        string
	From, Until  time.Time
	Page         int
}
type titleRow struct {
	order       string
	Board       publicBoard
	Key         uint64
	Title       string
	Created     domain.Time
	State       string
	Count       uint32
	publication *app.PostingSnapshot
	clock       func() time.Time
}
type searchView struct {
	Title, Board   string
	Query          url.Values
	Boards         []publicBoard
	Rows           []titleRow
	Previous, Next string
	HasMore        bool
}

var searchTemplate = webui.Template("search")

// parseTitleQuery はASCIIだけ小文字にし、日時を作成時刻の半開区間として検証する。
func parseTitleQuery(v url.Values) (q titleQuery, err error) {
	q.Page = 1
	for name, values := range v {
		if len(values) != 1 || !strings.Contains("|q|board|state|from|until|page|sort|", "|"+name+"|") {
			return q, ErrPostingRequest
		}
	}
	if !utf8.ValidString(v.Get("q")) || utf8.RuneCountInString(v.Get("q")) > 128 {
		return q, ErrPostingRequest
	}
	terms := strings.Fields(v.Get("q"))
	if len(terms) > 8 {
		return q, ErrPostingRequest
	}
	seen := map[string]bool{}
	for _, term := range terms {
		term = asciiFold(term)
		if !seen[term] {
			q.Terms = append(q.Terms, term)
			seen[term] = true
		}
	}
	q.Order = v.Get("sort")
	if q.Order != "" && q.Order != "newest" && q.Order != "oldest" && q.Order != "responses" {
		return q, ErrPostingRequest
	}
	q.Board, q.State = v.Get("board"), v.Get("state")
	if q.State != "" && q.State != "active" && q.State != "stopped" && q.State != "archived" {
		return q, ErrPostingRequest
	}
	for name, target := range map[string]*time.Time{"from": &q.From, "until": &q.Until} {
		if raw := v.Get(name); raw != "" {
			*target, err = time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				return q, ErrPostingRequest
			}
		}
	}
	if !q.From.IsZero() && !q.Until.IsZero() && !q.From.Before(q.Until) {
		return q, ErrPostingRequest
	}
	if raw, ok := v["page"]; ok {
		q.Page, err = strconv.Atoi(raw[0])
		if err != nil || q.Page < 1 || q.Page > 100 || strconv.Itoa(q.Page) != raw[0] {
			return q, ErrPostingRequest
		}
	}
	return q, nil
}
func asciiFold(s string) string {
	raw := []byte(s)
	for i, c := range raw {
		if c >= 'A' && c <= 'Z' {
			raw[i] = c + ('a' - 'A')
		}
	}
	return string(raw)
}

// containsASCIIFold は正規化済み語と元タイトルを比較し、走査ごとの文字列コピーを避ける。
// 非ASCII byteはそのまま比較するため、Unicodeの互換文字や大小文字を同一視しない。
func containsASCIIFold(title, term string) bool {
	if len(term) == 0 {
		return true
	}
	for start := 0; start <= len(title)-len(term); start++ {
		matched := true
		for j := 0; j < len(term); j++ {
			c := title[start+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != term[j] {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

func (q titleQuery) matches(s *app.ThreadSummary) bool {
	if q.State != "" && q.State != s.State {
		return false
	}
	created := time.Unix(0, int64(s.Created))
	if !q.From.IsZero() && created.Before(q.From) || !q.Until.IsZero() && !created.Before(q.Until) {
		return false
	}
	for _, term := range q.Terms {
		if !containsASCIIFold(s.Title, term) {
			return false
		}
	}
	return true
}

// titleResults は送信完了まで検索枠を所有する。Close後は候補を参照しない。
type titleResults struct {
	Rows    []titleRow
	More    bool
	once    sync.Once
	release func()
}

// Close は検索候補と共有予算を一度だけ解放する。
func (r *titleResults) Close() {
	if r != nil {
		r.once.Do(func() { r.Rows = nil; r.release() })
	}
}

const titleSearchBudget = 128 << 20
const titleSearchReservation = titleSearchBudget / 4
const titleSearchLimit = 5000

// reserveTitleSearch は走査・候補・応答を含む32MiB枠を即時取得する。
// HTTP送信中も保持し、遅い読者による候補配列の無制限な残留を防ぐ。
func (repo *Repository) reserveTitleSearch() bool {
	for {
		used := repo.searchReserved.Load()
		if used > titleSearchBudget-titleSearchReservation {
			return false
		}
		if repo.searchReserved.CompareAndSwap(used, used+titleSearchReservation) {
			return true
		}
	}
}

// titleNewer は全板共通の並びを定義する。IDは文字列化せず固定長で比較する。
func titleNewer(a, b titleRow) bool {
	if a.Created != b.Created {
		return a.Created > b.Created
	}
	if a.Key != b.Key {
		return a.Key > b.Key
	}
	return bytes.Compare(a.Board.ID[:], b.Board.ID[:]) < 0
}

// titleBefore は選択された順序を上位候補の選別と最終整列へ共用する。
func titleBefore(a, b titleRow) bool {
	if a.order == "oldest" && a.Created != b.Created {
		return a.Created < b.Created
	}
	if a.order == "responses" && a.Count != b.Count {
		return a.Count > b.Count
	}
	return titleNewer(a, b)
}

type titleHeap []titleRow

func (h titleHeap) Len() int           { return len(h) }
func (h titleHeap) Less(i, j int) bool { return titleBefore(h[j], h[i]) }
func (h titleHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *titleHeap) Push(v any)        { *h = append(*h, v.(titleRow)) }
func (h *titleHeap) Pop() any {
	n := len(*h) - 1
	v := (*h)[n]
	(*h)[n] = titleRow{}
	*h = (*h)[:n]
	return v
}

// titleCollector は全一致件数に比例する配列を作らず、上位5000候補だけを維持する。
type titleCollector struct {
	order                                          string
	rows                                           titleHeap
	scanned, matches, metadataBytes, retainedBytes int
}

func (c *titleCollector) add(row titleRow, publish func() *app.PostingSnapshot) error {
	row.order = c.order
	c.scanned++
	c.metadataBytes += len(row.Title) + 256
	if c.scanned > 100000 || c.metadataBytes > titleSearchBudget {
		return errors.New("search metadata budget exceeded")
	}
	if publish == nil {
		return nil
	}
	c.matches++
	if len(c.rows) == titleSearchLimit && !titleBefore(row, c.rows[0]) {
		return nil
	}
	bytes := len(row.Title) + 512
	if len(c.rows) == titleSearchLimit {
		bytes -= len(c.rows[0].Title) + 512
	}
	// 予算の半分を候補に使い、残りを走査・sort・HTML応答の余裕として残す。
	if c.retainedBytes+bytes > titleSearchReservation/2 {
		return errors.New("search result budget exceeded")
	}
	row.publication = publish()
	if row.publication == nil {
		return ErrPostingUnavailable
	}
	c.retainedBytes += bytes
	if len(c.rows) < titleSearchLimit {
		heap.Push(&c.rows, row)
	} else {
		c.rows[0] = row
		heap.Fix(&c.rows, 0)
	}
	return nil
}

// searchTitles は本文を読まず、所有列から取得した公開要約だけを走査する。
// 呼出し元は成功時の候補を送信し終わった後に必ずCloseする。
func (repo *Repository) searchTitles(ctx context.Context, q titleQuery, boards []publicBoard) (*titleResults, error) {
	repo.searchOnce.Do(func() { repo.searchWorkers = make(chan struct{}, 4); repo.searchRequests = make(chan struct{}, 68) })
	select {
	case repo.searchRequests <- struct{}{}:
	default:
		return nil, errors.New("search capacity exhausted")
	}
	budget := false
	result := &titleResults{release: func() {
		if budget {
			repo.searchReserved.Add(-titleSearchReservation)
		}
		<-repo.searchRequests
	}}
	success := false
	defer func() {
		if !success {
			result.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	select {
	case repo.searchWorkers <- struct{}{}:
		defer func() { <-repo.searchWorkers }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	budget = repo.reserveTitleSearch()
	if !budget {
		return nil, errors.New("shared search budget exhausted")
	}
	collector := titleCollector{order: q.Order, rows: make(titleHeap, 0, titleSearchLimit)}
	for _, board := range boards {
		if q.Board != "" && q.Board != board.Key {
			continue
		}
		b, e := repo.postingOwner(board.ID)
		if e != nil {
			return nil, e
		}
		_, e = b.worker.SubmitIdle(ctx, func() (any, error) {
			if b.stopped {
				return nil, ErrPostingUnavailable
			}
			now := domain.Time(b.clock().UnixNano())
			for key, p := range b.threads {
				if e := ctx.Err(); e != nil {
					return nil, e
				}
				s := p.Summary(now)
				if s == nil {
					continue
				}
				row := titleRow{Board: board, Key: key, Title: s.Title, Created: s.Created, State: s.State, Count: s.Count, clock: b.clock}
				var publish func() *app.PostingSnapshot
				if q.matches(s) {
					publish = func() *app.PostingSnapshot { return p.PublicationSnapshot(now) }
				}
				if e := collector.add(row, publish); e != nil {
					return nil, e
				}
			}
			return nil, nil
		})
		if e != nil {
			return nil, e
		}
	}
	sort.Slice(collector.rows, func(i, j int) bool { return titleBefore(collector.rows[i], collector.rows[j]) })
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	result.Rows, result.More = collector.rows, collector.matches > titleSearchLimit
	success = true
	return result, nil
}

func (repo *Repository) searchPage(w http.ResponseWriter, r *http.Request, boards []publicBoard) {
	if !listingMethod(w, r) {
		return
	}
	v, e := url.ParseQuery(r.URL.RawQuery)
	q, err := parseTitleQuery(v)
	if e != nil || err != nil {
		threadError(w, r, 400, "検索条件を確認してください。")
		return
	}
	if q.Board != "" {
		found := false
		for _, b := range boards {
			found = found || b.Key == q.Board
		}
		if !found {
			threadError(w, r, 404, "板が見つかりません。")
			return
		}
	}
	result, e := repo.searchTitles(r.Context(), q, boards)
	if e != nil {
		w.Header().Set("Retry-After", "1")
		threadError(w, r, 503, "現在検索できません。")
		return
	}
	defer result.Close()
	rows, more := result.Rows, result.More
	if q.Page > max(1, (len(rows)+49)/50) {
		threadError(w, r, 404, "ページが見つかりません。")
		return
	}
	page := searchView{Title: "タイトル検索", Query: v, Boards: boards, HasMore: more, Rows: rows[min((q.Page-1)*50, len(rows)):min(q.Page*50, len(rows))]}
	link := func(n int) string {
		copy := url.Values{}
		for k, values := range v {
			copy[k] = append([]string{}, values...)
		}
		copy.Set("page", strconv.Itoa(n))
		return "/search?" + copy.Encode()
	}
	if q.Page > 1 {
		page.Previous = link(q.Page - 1)
	}
	if q.Page*50 < len(rows) {
		page.Next = link(q.Page + 1)
	}
	// 板ごとの時計でリースを取得し、時計逆行や削除でも古い候補を再公開しない。
	response := &publicResponse{ResponseWriter: w, clock: time.Now, ctx: r.Context()}
	defer response.Close()
	controller := http.NewResponseController(w)
	for _, row := range page.Rows {
		lease, e := row.publication.AcquirePublic(domain.Time(row.clock().UnixNano()), func() { _ = controller.SetWriteDeadline(time.Now()) })
		if e != nil {
			threadError(w, r, 503, "検索結果が変わりました。再検索してください。")
			return
		}
		response.leases = append(response.leases, lease)
		response.leaseClocks = append(response.leaseClocks, row.clock)
	}
	writeSearch(response, r, page)
}
