// 永続投稿の公開snapshotだけを使い、read.cgiの閲覧HTMLを生成する。
package bootstrap

import (
	"bytes"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/textcodec"
	"oimobbs/internal/webui"
	"strconv"
	"strings"
)

type threadRow struct {
	Number                 int
	Name, Mail, Date, Body string
}
type threadPage struct {
	Title, Key, Board string
	MoveTarget        string
	Count             uint32
	Rows              []threadRow
	Previous, Next    string
	CanReply          bool
	CapOnly           bool
}

var threadTemplate = webui.Template("thread")

// BoardWebHandler は解決済みの一板について投稿と投稿後の閲覧先を接続する内部ハンドラ。
// 複数板の振分け・板一覧・専ブラDAT・公開serveは上位層で接続する。
func (repo *Repository) BoardWebHandler(owner domain.ID, observer *evidence.HTTPObserver) http.Handler {
	posting := repo.WebPostingHandler(owner, observer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var denied bool
		w, denied = repo.readingBoardGate(w, r, owner)
		if denied {
			return
		}
		if r.URL.Path == "/web/post" {
			posting.ServeHTTP(w, r)
			return
		}
		repo.threadPage(w, r, owner)
	})
}
func threadError(w http.ResponseWriter, r *http.Request, status int, message string) {
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		_, _ = fmt.Fprint(w, message)
	}
}
func (repo *Repository) threadPage(w http.ResponseWriter, r *http.Request, owner domain.ID) {
	postingHeaders(w)
	w.Header().Set("Cache-Control", "no-cache")
	base, e := parseOrigin(repo.cfg.Public.BaseURL)
	if e != nil || (base.Scheme == "https") != (r.TLS != nil) {
		threadError(w, r, 400, "接続先を確認してください。")
		return
	}
	host, e := parseOrigin(base.Scheme + "://" + r.Host)
	if e != nil || normalizedOrigin(host) != normalizedOrigin(base) {
		threadError(w, r, 400, "接続先を確認してください。")
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/test/read.cgi/") {
		threadError(w, r, 404, "ページが見つかりません。")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		threadError(w, r, 405, "この操作は利用できません。")
		return
	}
	b, e := repo.postingOwner(owner)
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	key, selection, page, e := threadRequest(r, b.slug)
	if e != nil {
		threadError(w, r, 400, "レスの指定を確認してください。")
		return
	}
	snapshot, status := b.publicSnapshot(key, domain.Time(b.clock().UnixNano()))
	if status != 200 {
		threadError(w, r, status, "スレッドを表示できません。")
		return
	}
	selected, e := compat.SelectPosts(selection, int(snapshot.PostCount), page)
	if e != nil {
		threadError(w, r, 400, "レスの指定を確認してください。")
		return
	}
	cacheKey := fmt.Sprintf("thread-html:%s:%s:%d:%d:%d:%s:%d", owner, b.slug, key, snapshot.Generation, snapshot.Revision, selection, page)
	body, e := repo.feedCompression.Render(r.Context(), cacheKey, func() ([]byte, error) {
		rows, e := threadRows(snapshot.DAT, snapshot.PostCount, selected)
		if e != nil {
			return nil, e
		}
		view := threadPage{Board: b.slug, Title: snapshot.Title, Key: fmt.Sprint(key), Count: snapshot.PostCount, Rows: rows, CanReply: snapshot.CanReply, CapOnly: snapshot.CapOnly, MoveTarget: snapshot.MoveTarget}
		path := fmt.Sprintf("/test/read.cgi/%s/%d/%s", b.slug, key, selection)
		if page > 1 {
			view.Previous = fmt.Sprintf("%s?page=%d", path, page-1)
		}
		if _, e = compat.SelectPosts(selection, int(snapshot.PostCount), page+1); e == nil {
			view.Next = fmt.Sprintf("%s?page=%d", path, page+1)
		}
		var body bytes.Buffer
		if e = threadTemplate.Execute(&body, view); e != nil {
			return nil, e
		}
		return body.Bytes(), nil
	})
	if e != nil {
		threadError(w, r, 503, "現在閲覧できません。")
		return
	}
	writer, e := publicWriter(w, r, snapshot, b.clock)
	if e != nil {
		threadError(w, r, 410, "スレッドを表示できません。")
		return
	}
	defer writer.Close()
	repo.writeFeed(writer, r, "text/html; charset=UTF-8", body, nil)
}
func threadRequest(r *http.Request, slug string) (uint64, string, int, error) {
	if r.URL.EscapedPath() != r.URL.Path {
		return 0, "", 0, compat.ErrSelection
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/test/read.cgi/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != slug {
		return 0, "", 0, compat.ErrSelection
	}
	key, e := strconv.ParseUint(parts[1], 10, 64)
	if e != nil || key == 0 || fmt.Sprint(key) != parts[1] {
		return 0, "", 0, compat.ErrSelection
	}
	selection := ""
	if len(parts) == 3 {
		selection = parts[2]
	}
	query, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(query["page"]) > 1 {
		return 0, "", 0, compat.ErrSelection
	}
	page := 1
	if raw, ok := query["page"]; ok {
		page, e = strconv.Atoi(raw[0])
		if e != nil || page < 1 || strconv.Itoa(page) != raw[0] {
			return 0, "", 0, compat.ErrSelection
		}
	}
	return key, selection, page, nil
}

// threadRows は検証済みsnapshotの行数と選択行を照合し、表示対象だけ文字列へ戻す。
// 保存層で全行の文字コードを検証済みのDAT専用。HTMLタグは信頼しない。
func threadRows(dat []byte, count uint32, numbers []int) ([]threadRow, error) {
	if !bytes.HasSuffix(dat, []byte("\n")) {
		return nil, compat.ErrForm
	}
	lines := bytes.Split(dat[:len(dat)-1], []byte("\n"))
	if len(lines) != int(count) {
		return nil, compat.ErrForm
	}
	rows := make([]threadRow, 0, len(numbers))
	for _, number := range numbers {
		if number < 1 || number > len(lines) {
			return nil, compat.ErrSelection
		}
		decoded, e := textcodec.Decode(lines[number-1])
		if e != nil {
			return nil, e
		}
		fields := strings.Split(decoded, "<>")
		if len(fields) != 5 {
			return nil, compat.ErrForm
		}
		rows = append(rows, threadRow{Number: number, Name: compat.PlainDATName(fields[0]), Mail: html.UnescapeString(fields[1]), Date: html.UnescapeString(fields[2]), Body: html.UnescapeString(strings.ReplaceAll(fields[3], "<br>", "\n"))})
	}
	return rows, nil
}
