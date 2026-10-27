// 検索の全板上位集合、10万件上限、遅い応答を含む共有予算の回収を検査する。
package bootstrap

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
)

func searchRowsFixture(n int) []titleRow {
	rows := make([]titleRow, n)
	for i := range rows {
		// 同時刻・同キーが異なる板にある条件も含め、標準並びの全比較キーを使う。
		var id domain.ID
		id[0], id[15] = byte(i%128), byte(i%251)
		rows[i] = titleRow{Board: publicBoard{ID: id}, Key: uint64(i / 3), Created: domain.Time(i/7 + 1), Title: fmt.Sprintf("検索対象 日本語 Topic %06d", i), State: "active"}
	}
	rand.New(rand.NewPCG(42, 57)).Shuffle(len(rows), func(i, j int) { rows[i], rows[j] = rows[j], rows[i] })
	return rows
}

func TestTitleCollectorHundredThousand(t *testing.T) {
	rows := searchRowsFixture(100000)
	c := titleCollector{rows: make(titleHeap, 0, titleSearchLimit)}
	publish := func() *app.PostingSnapshot { return &app.PostingSnapshot{} }
	for _, row := range rows {
		if err := c.add(row, publish); err != nil {
			t.Fatal(err)
		}
		if len(c.rows) > titleSearchLimit {
			t.Fatal("unbounded result allocation")
		}
	}
	sort.Slice(rows, func(i, j int) bool { return titleNewer(rows[i], rows[j]) })
	sort.Slice(c.rows, func(i, j int) bool { return titleNewer(c.rows[i], c.rows[j]) })
	if c.scanned != 100000 || c.matches != 100000 || len(c.rows) != 5000 || c.retainedBytes > titleSearchReservation/2 {
		t.Fatal("wrong scan/result accounting", c.scanned, c.matches, len(c.rows), c.retainedBytes)
	}
	for i := range c.rows {
		got, want := c.rows[i], rows[i]
		if got.Key != want.Key || got.Created != want.Created || got.Board.ID != want.Board.ID {
			t.Fatalf("row %d differs: %v / %v", i, got, want)
		}
	}
	if err := c.add(rows[0], nil); err == nil {
		t.Fatal("100001st metadata row accepted")
	}
}

func TestTitleCollectorBudgets(t *testing.T) {
	publish := func() *app.PostingSnapshot { return &app.PostingSnapshot{} }
	c := titleCollector{}
	row := titleRow{Title: strings.Repeat("x", titleSearchReservation/2), Created: 1}
	if err := c.add(row, publish); err == nil || len(c.rows) != 0 {
		t.Fatal("oversized candidate retained")
	}
	c = titleCollector{}
	row.Title = strings.Repeat("x", titleSearchBudget)
	if err := c.add(row, nil); err == nil {
		t.Fatal("metadata budget ignored for unmatched row")
	}
	c = titleCollector{}
	row.Title = "nonmatch"
	if err := c.add(row, nil); err != nil || c.scanned != 1 || c.matches != 0 || len(c.rows) != 0 {
		t.Fatal("nonmatching scan", err)
	}
}

func TestSearchSharedBudgetThroughResponse(t *testing.T) {
	repo := &Repository{}
	var results []*titleResults
	for i := 0; i < 4; i++ {
		result, err := repo.searchTitles(context.Background(), titleQuery{Page: 1}, nil)
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	if repo.searchReserved.Load() != titleSearchBudget || len(repo.searchWorkers) != 0 || len(repo.searchRequests) != 4 {
		t.Fatal("response reservation released prematurely")
	}
	if result, err := repo.searchTitles(context.Background(), titleQuery{}, nil); err == nil {
		result.Close()
		t.Fatal("response budget overcommitted")
	}
	if repo.searchReserved.Load() != titleSearchBudget || len(repo.searchRequests) != 4 {
		t.Fatal("rejection leaked or stole reservation")
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Go(results[0].Close)
	}
	group.Wait()
	if repo.searchReserved.Load() != titleSearchBudget-titleSearchReservation {
		t.Fatal("Close was not idempotent")
	}
	result, err := repo.searchTitles(context.Background(), titleQuery{}, nil)
	if err != nil {
		t.Fatal("released budget not reusable", err)
	}
	result.Close()
	for _, result := range results {
		result.Close()
	}
	if repo.searchReserved.Load() != 0 || len(repo.searchRequests) != 0 {
		t.Fatal("response cleanup leaked")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := repo.searchTitles(ctx, titleQuery{}, nil); err == nil {
		result.Close()
		t.Fatal("cancelled search accepted")
	}
	if repo.searchReserved.Load() != 0 || len(repo.searchWorkers) != 0 || len(repo.searchRequests) != 0 {
		t.Fatal("cancelled query leaked")
	}
}

// BenchmarkTitleSearchHundredThousand は保存・HTTPを含めず、公開要約走査と上位選択を同じ固定集合で測る。
func BenchmarkTitleSearchHundredThousand(b *testing.B) {
	rows := searchRowsFixture(100000)
	for name, terms := range map[string][]string{"all": nil, "and": {"日本語", "topic", "000"}, "none": {"absent"}} {
		b.Run(name, func(b *testing.B) {
			q := titleQuery{Terms: terms}
			publish := func() *app.PostingSnapshot { return &app.PostingSnapshot{} }
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				c := titleCollector{rows: make(titleHeap, 0, titleSearchLimit)}
				for _, row := range rows {
					s := app.ThreadSummary{Title: row.Title, Created: row.Created, State: row.State}
					var get func() *app.PostingSnapshot
					if q.matches(&s) {
						get = publish
					}
					if err := c.add(row, get); err != nil {
						b.Fatal(err)
					}
				}
				sort.Slice(c.rows, func(i, j int) bool { return titleNewer(c.rows[i], c.rows[j]) })
			}
		})
	}
}

func TestSearchHTTPReleasesBudget(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	for _, raw := range []string{"/search", "/search?page=2"} {
		request := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+raw, nil)
		recorder := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(recorder, request)
		if repo.searchReserved.Load() != 0 || len(repo.searchRequests) != 0 {
			t.Fatal("HTTP success/error leaked response budget")
		}
	}
}

func TestContainsASCIIFold(t *testing.T) {
	words := []string{"", "ABC", "Abc日本語", "日本語ABC日本", "ÄＡİΣ", "🙂Zz", "aあb", "あアｱ", "ABABA"}
	for _, title := range words {
		for _, query := range words {
			term := asciiFold(query)
			if got, want := containsASCIIFold(title, term), strings.Contains(asciiFold(title), term); got != want {
				t.Fatalf("%q contains %q: %v / %v", title, term, got, want)
			}
		}
	}
}
