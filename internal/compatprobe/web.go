// 試験サーバの板一覧、スレッド一覧、本文を別の表示状態で描画する。
package compatprobe

import (
	"bytes"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"oimobbs/internal/compat"
)

// webPost は画面で使用する公開項目だけを保持する。
type webPost struct {
	Number                     uint32
	Name, Trip, ID, Date, Body string
}

type webPage struct {
	Title     string
	Notice    string
	Home      bool
	Thread    bool
	Rows      []compat.SubjectEntry
	Posts     []webPost
	Boards    []menuBoard
	BoardPath string
	Slug      string
	Key       string
	Form      postForm
}

var page = mustPage()

func mustPage() *template.Template {
	return template.Must(template.Must(postFormTemplate.Clone()).New("page").Parse(`<!doctype html>
<html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{.Title}} - OimoBBS互換試験</title></head>
<body><header><h1>{{.Title}}</h1><p>{{.Notice}}</p></header>
<nav aria-label="掲示板ナビゲーション"><a href="/">板一覧</a>{{if .Thread}} / <a href="{{.BoardPath}}">スレッド一覧</a>{{end}}</nav>
<main>{{if .Home}}<h2>互換試験</h2><ul>{{range .Boards}}<li><a href="{{.Path}}">{{.Name}}</a></li>{{end}}</ul>
{{else if .Thread}}{{range .Posts}}<article><h2>{{.Number}} : {{.Name}}{{if .Trip}} ◆{{.Trip}}{{end}} {{.Date}}{{if .ID}} ID:{{.ID}}{{end}}</h2><pre>{{.Body}}</pre></article>{{end}}<h2>返信する</h2>{{template "post" .Form}}
{{else}}<h2>スレッド一覧</h2>{{range .Rows}}<p><a href="/test/read.cgi/{{$.Slug}}/{{.Key}}/">{{.Title}} ({{.Count}})</a></p>{{else}}<p>まだスレッドがありません。</p>{{end}}<h2>スレッドを作成する</h2>{{template "post" .Form}}{{end}}</main></body></html>`))
}

// web は公開用の画面データを確定後、ロックを解放してHTMLを生成する。
func (s *Server) web(w http.ResponseWriter, r *http.Request) {
	view := webPage{Title: s.name, Notice: notice, Slug: s.slug, BoardPath: "/" + s.slug + "/"}
	switch {
	case r.URL.Path == "/":
		view.Title, view.Home = "板一覧", true
		view.Boards = s.menuBoards()
	case strings.HasPrefix(r.URL.Path, "/test/read.cgi/"+s.slug+"/"):
		var status int
		view, status = s.threadPage(r.URL.Path)
		if status != http.StatusOK {
			http.Error(w, http.StatusText(status), status)
			return
		}
	default:
		s.mu.Lock()
		view.Rows = s.rows()
		s.mu.Unlock()
	}
	if !view.Home {
		view.Form = s.newPostForm(w, r, view.Key)
		w.Header().Set("Cache-Control", "no-store")
	}
	var b bytes.Buffer
	if err := page.Execute(&b, view); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	output(w, r, "text/html; charset=UTF-8", b.Bytes())
}

// threadPage は所有状態から私情報を含まない本文表示を取り出す。
func (s *Server) threadPage(path string) (webPage, int) {
	view := webPage{Notice: notice, Thread: true, Slug: s.slug, BoardPath: "/" + s.slug + "/"}
	parts := strings.Split(strings.TrimPrefix(path, "/test/read.cgi/"+s.slug+"/"), "/")
	key, ok := parseKey(parts[0])
	if !ok || len(parts) > 2 {
		return view, http.StatusNotFound
	}
	selection := ""
	if len(parts) == 2 {
		selection = parts[1]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	thread := s.threads[key]
	if thread == nil {
		return view, http.StatusNotFound
	}
	indexes, err := compat.SelectPosts(selection, len(thread.Posts), 1)
	if err != nil {
		return view, http.StatusBadRequest
	}
	view.Title = thread.Title
	view.Key = strconv.FormatUint(key, 10)
	for _, i := range indexes {
		post := thread.Posts[i-1]
		view.Posts = append(view.Posts, webPost{Number: post.Number, Name: post.Name, Trip: post.Identity.Trip, ID: post.Identity.ID + post.Identity.Suffix, Date: post.Identity.DateText, Body: post.Body})
	}
	return view, http.StatusOK
}
