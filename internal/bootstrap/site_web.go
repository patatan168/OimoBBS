// 確定済みの板を解決し、公開一覧・投稿・閲覧の内部ルーターへ接続する。
package bootstrap

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
	"sort"
	"strconv"
	"strings"
)

type publicBoard struct {
	CategoryID    domain.ID
	CategoryName  string
	CategoryOrder uint32
	Hidden        bool
	ID            domain.ID
	Key, Name     string
}
type publicThread struct {
	publication *app.PostingSnapshot
	Key         uint64
	Title       string
	Count       uint32
	BumpKind    string
	Bump        domain.U64
}
type listingPage struct {
	BoardGroups    []publicBoardGroup
	Hidden         bool
	IsList         bool
	HasArchive     bool
	Title, Board   string
	Boards         []publicBoard
	Threads        []publicThread
	Previous, Next string
	Rules          []ruleParagraph
}

var listingTemplate = webui.Template("list")

// SiteWebHandler は確定済み板の一覧とWeb投稿/閲覧を振り分ける内部ルーター。
// 公開起動・管理・規制を備えた製品serveの代用にはしない。
func (repo *Repository) SiteWebHandler(observer *evidence.HTTPObserver) http.Handler {
	base, originErr := parseOrigin(repo.cfg.Public.BaseURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postingHeaders(w)
		if originErr != nil || (base.Scheme == "https") != (r.TLS != nil) {
			threadError(w, r, 400, "接続先を確認してください。")
			return
		}
		host, e := parseOrigin(base.Scheme + "://" + r.Host)
		if e != nil || normalizedOrigin(host) != normalizedOrigin(base) {
			threadError(w, r, 400, "接続先を確認してください。")
			return
		}
		if !canonicalRequestPath(r) {
			threadError(w, r, 400, "URLを確認してください。")
			return
		}
		if webui.ServePublicAsset(w, r) {
			return
		}
		if !repo.admitAttempt(w, r) {
			return
		}
		if r.URL.Path == "/robots.txt" {
			repo.robotsPage(w, r)
			return
		}
		var readingDenied bool
		w, readingDenied = repo.readingGate(w, r, "site")
		if readingDenied {
			return
		}
		var denied bool
		w, denied = repo.reprintCrawlerGate(w, r)
		if denied {
			return
		}
		if repo.hiddenBoardWebGate(w, r) {
			return
		}
		if r.URL.Path == "/web/terms" {
			repo.publicConsentPage(w, r)
			return
		}
		path := r.URL.Path
		if path == "/test/bbs.cgi" {
			repo.legacyPostingPage(w, r, observer)
			return
		}
		parts := strings.Split(path, "/")
		datRoute := len(parts) == 4 && parts[0] == "" && parts[2] == "dat" && strings.HasSuffix(parts[3], ".dat")
		threadRoute := strings.HasPrefix(path, "/test/read.cgi/")
		webPostRoute := path == "/web/post"
		if datRoute || threadRoute || webPostRoute || legacyFeedPath(path) {
			slug := parts[1]
			if webPostRoute {
				query, err := url.ParseQuery(r.URL.RawQuery)
				if err != nil || len(query["bbs"]) != 1 || query.Get("bbs") == "" {
					threadError(w, r, 400, "板を指定してください。")
					return
				}
				slug = query.Get("bbs")
			}
			if threadRoute {
				slug = strings.Split(strings.TrimPrefix(path, "/test/read.cgi/"), "/")[0]
			}
			board, err := repo.webBoard(slug)
			if err != nil {
				threadError(w, r, 503, "現在閲覧できません。")
			} else if board == nil {
				threadError(w, r, 404, "板が見つかりません。")
			} else if threadRoute || webPostRoute {
				evidence.AnnotateOptionalBoard(r.Context(), board.ID)
				repo.BoardWebHandler(board.ID, observer).ServeHTTP(w, r)
			} else {
				if !datRoute {
					evidence.AnnotateOptionalBoard(r.Context(), board.ID)
				}
				repo.legacyFeed(w, r, *board)
			}
			return
		}
		title, boards, e := repo.webBoards()
		if e != nil {
			threadError(w, r, 503, "現在閲覧できません。")
			return
		}
		if path == "/reports" || path == "/reports/lookup" {
			repo.reportsHTTP(w, r)
			return
		}
		if path == "/search" || path == "/" || path == "/bbsmenu.html" || path == "/bbsmenu.json" {
			boards = repo.readableBoards(r, boards)
			w = repo.readingListWriter(w, r, boards)
		}
		if path == "/search" {
			repo.searchPage(w, r, searchableBoards(boards))
			return
		}
		if path == "/" {
			if !listingMethod(w, r) {
				return
			}
			repo.writeListing(w, r, listingPage{Title: title, Boards: boards, BoardGroups: groupPublicBoards(title, boards)})
			return
		}
		if path == "/bbsmenu.html" || path == "/bbsmenu.json" {
			repo.legacyMenu(w, r, title, boards)
			return
		}
		slug := ""
		switch {
		case path == "/web/post":
			q, e := url.ParseQuery(r.URL.RawQuery)
			if e != nil || len(q["bbs"]) != 1 || q.Get("bbs") == "" {
				threadError(w, r, 400, "板を指定してください。")
				return
			}
			slug = q.Get("bbs")
		case strings.HasPrefix(path, "/test/read.cgi/"):
			slug = strings.Split(strings.TrimPrefix(path, "/test/read.cgi/"), "/")[0]
		case legacyFeedPath(path):
			slug = strings.Split(path, "/")[1]
		case strings.HasSuffix(path, "/index.html") || strings.HasSuffix(path, "/subback.html"):
			parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
			if len(parts) == 2 {
				slug = parts[0]
			}
		case strings.HasPrefix(path, "/") && strings.HasSuffix(path, "/"):
			slug = strings.Trim(path, "/")
			if strings.Contains(slug, "/") {
				slug = ""
			}
		}
		var board *publicBoard
		for i := range boards {
			if boards[i].Key == slug {
				board = &boards[i]
				break
			}
		}
		if board == nil {
			board, e = repo.webBoard(slug)
			if e != nil {
				threadError(w, r, 503, "現在閲覧できません。")
				return
			}
		}
		if board == nil {
			threadError(w, r, 404, "板が見つかりません。")
			return
		}
		evidence.AnnotateOptionalBoard(r.Context(), board.ID)
		if path == "/"+slug+"/" || path == "/"+slug+"/index.html" || path == "/"+slug+"/subback.html" {
			repo.boardListing(w, r, *board)
			return
		}
		if legacyFeedPath(path) {
			repo.legacyFeed(w, r, *board)
			return
		}
		if path == "/web/post" || strings.HasPrefix(path, "/test/read.cgi/") {
			repo.BoardWebHandler(board.ID, observer).ServeHTTP(w, r)
			return
		}
		threadError(w, r, 404, "ページが見つかりません。")
	})
}

// webBoard はDAT・Webスレッド閲覧で不要なサイトJSONの復号と全板の並べ替えを省く。公開状態は毎回確認する。
func (repo *Repository) webBoard(slug string) (*publicBoard, error) {
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	if err := repo.available(); err != nil {
		return nil, err
	}
	for id, board := range repo.posting {
		if board.matchesKey(slug) {
			return &publicBoard{ID: id, Key: board.boardKey(), Name: board.boardName(), Hidden: board.hidden.Load()}, nil
		}
	}
	return nil, nil
}

// webBoards はサイト所有mutexの下で確定済みメタデータだけをコピーする。毎要求ディスク走査しない。
func (repo *Repository) webBoards() (string, []publicBoard, error) {
	repo.mu.RLock()
	defer repo.mu.RUnlock()
	if e := repo.available(); e != nil {
		return "", nil, e
	}
	var site siteState
	if e := strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site); e != nil {
		return "", nil, e
	}
	dirs, err := siteDirectories(repo.site.State())
	if err != nil {
		return "", nil, err
	}
	categories := map[domain.ID]category{}
	for _, c := range site.Categories {
		categories[c.ID] = c
	}
	rows := make([]publicBoard, 0, len(repo.posting))
	for id, b := range repo.posting {
		fallback := site.Name
		if len(site.Categories) > 0 {
			fallback = "未分類"
		}
		row := publicBoard{CategoryName: fallback, ID: id, Key: b.boardKey(), Name: b.boardName(), Hidden: b.hidden.Load(), CategoryOrder: ^uint32(0)}
		if d := dirs[id]; d != nil && d.CategoryID != nil {
			c := categories[*d.CategoryID]
			row.CategoryID, row.CategoryName, row.CategoryOrder = c.ID, c.Name, c.Order
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return site.Name, rows, nil
}
func listingMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == "GET" || r.Method == "HEAD" {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	threadError(w, r, 405, "この操作は利用できません。")
	return false
}
func (repo *Repository) boardListing(w http.ResponseWriter, r *http.Request, board publicBoard) {
	var denied bool
	w, denied = repo.readingBoardGate(w, r, board.ID)
	if denied {
		return
	}
	if !listingMethod(w, r) {
		return
	}
	q, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(q["page"]) > 1 {
		threadError(w, r, 400, "ページを確認してください。")
		return
	}
	page := 1
	if raw, exists := q["page"]; exists {
		page, e = strconv.Atoi(raw[0])
		if e != nil || page < 1 || strconv.Itoa(page) != raw[0] {
			threadError(w, r, 400, "ページを確認してください。")
			return
		}
	}
	rows, archive, e := repo.threadListings(r, board.ID)
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	isList := strings.HasSuffix(r.URL.Path, "/subback.html")
	limit := 20
	if isList {
		limit = 100
	}
	pages := max(1, (len(rows)+limit-1)/limit)
	if page > pages {
		threadError(w, r, 404, "ページが見つかりません。")
		return
	}
	b, err := repo.postingOwner(board.ID)
	if err != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	ruleValue, err := b.worker.Submit(r.Context(), func() (any, error) { return b.publicLocalRules() })
	if err != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	view := listingPage{Hidden: board.Hidden, Rules: ruleValue.(AdminLocalRules).Settings.Rules, HasArchive: archive != nil, IsList: isList, Title: board.Name, Board: board.Key, Threads: rows[(page-1)*limit : min(page*limit, len(rows))]}
	if page > 1 {
		view.Previous = fmt.Sprintf("%s?page=%d", r.URL.Path, page-1)
	}
	if page < pages {
		view.Next = fmt.Sprintf("%s?page=%d", r.URL.Path, page+1)
	}
	guarded := append([]publicThread{}, view.Threads...)
	if archive != nil {
		guarded = append(guarded, publicThread{publication: archive})
	}
	writer, e := repo.publicListingWriter(w, r, board.ID, guarded)
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	defer writer.Close()
	repo.writeListing(writer, r, view)
}
func (repo *Repository) threadListing(r *http.Request, owner domain.ID) ([]publicThread, error) {
	rows, _, err := repo.threadListings(r, owner)
	return rows, err
}

// threadListings は保存待ちをせず、各スレッドの確定済み要約と同世代の公開権限を取得する。
// 複数スレッドの読取り中の投稿は許し、送信前・送信中のリースで削除と期限を再検査する。
func (repo *Repository) threadListings(r *http.Request, owner domain.ID) ([]publicThread, *app.PostingSnapshot, error) {
	b, e := repo.postingOwner(owner)
	if e != nil {
		return nil, nil, e
	}
	if err := r.Context().Err(); err != nil {
		return nil, nil, err
	}
	if b.listingStopped.Load() {
		return nil, nil, ErrPostingUnavailable
	}
	select {
	case <-b.worker.Done():
		return nil, nil, ErrPostingUnavailable
	default:
	}
	now := domain.Time(b.clock().UnixNano())
	rows := []publicThread{}
	var archive *app.PostingSnapshot
	b.publicReaders.Range(func(key, value any) bool {
		s, publication, status := value.(*app.PublicReader).Listing(now)
		if status != 200 {
			return true
		}
		if s.State == "archived" {
			if archive == nil {
				archive = publication
			}
			return true
		}
		rows = append(rows, publicThread{Key: key.(uint64), Title: s.Title, Count: s.Count, BumpKind: s.BumpKind, Bump: s.BumpValue, publication: publication})
		return true
	})
	if receipt := b.receipt.Load(); receipt != nil {
		rows = append(rows, publicThread{Key: reportReceiptKey, Title: reportReceiptTitle, Count: 1, BumpKind: "receipt", publication: receipt})
	}
	if b.listingStopped.Load() {
		return nil, nil, ErrPostingUnavailable
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Key == reportReceiptKey || b.Key == reportReceiptKey {
			return b.Key == reportReceiptKey && a.Key != reportReceiptKey
		}
		if a.BumpKind != b.BumpKind {
			return a.BumpKind == "normal"
		}
		if a.Bump != b.Bump {
			if a.BumpKind == "bottom" {
				return a.Bump < b.Bump
			}
			return a.Bump > b.Bump
		}
		return a.Key < b.Key
	})
	return rows, archive, nil
}
func (repo *Repository) writeListing(w http.ResponseWriter, r *http.Request, view listingPage) {
	var body bytes.Buffer
	if e := listingTemplate.Execute(&body, view); e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	repo.writeFeed(w, r, "text/html; charset=UTF-8", body.Bytes(), nil)
}
