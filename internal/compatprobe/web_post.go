// UTF-8のスレ立て・返信・確認画面を、専ブラと同じ受理処理へ接続する。
package compatprobe

import (
	"bytes"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"oimobbs/internal/compat"
	"strings"
)

type postForm struct{ Board, Key, Subject, Name, Mail, Body, RequestID, CSRF string }

var postFormTemplate = template.Must(template.New("post").Parse(`{{define "post"}}<form method="post" action="/web/post" accept-charset="UTF-8">
<input type="hidden" name="bbs" value="{{.Board}}"><input type="hidden" name="key" value="{{.Key}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="oimo_request_id" value="{{.RequestID}}">
{{if not .Key}}<p><label>スレッドタイトル <input name="subject" value="{{.Subject}}" required maxlength="128"></label></p>{{end}}
<p><label>名前（任意・#以降はトリップ秘密） <input name="FROM" value="{{.Name}}" autocomplete="off"></label></p>
<p><label>メール（任意） <input name="mail" value="{{.Mail}}"></label></p>
<p><label>本文 <textarea name="MESSAGE" rows="6" cols="40" required>{{.Body}}</textarea></label></p>
<p>日付ごとのIDを表示します。IPアドレスは公開しません。</p><button type="submit">内容を確認</button></form>{{end}}`))
var confirmationPage = template.Must(template.New("confirm").Parse(`<!doctype html><html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>書き込み確認</title></head><body><h1>書き込み確認</h1><p>{{.Notice}}</p><p>名前：{{.Input.Name}} {{if .Input.Trip}}◆{{.Input.Trip}}{{end}}</p><p>メール：{{.Input.Mail}}</p><p>{{.Input.Title}}</p><pre>{{.Input.Body}}</pre><p>日付ごとのIDを表示します。IPアドレスは公開しません。</p>
<form method="post" action="/web/post" accept-charset="UTF-8">{{range $key,$value := .Fields}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}<input type="hidden" name="oimo_confirm" value="{{.Token}}"><button type="submit">この内容で書き込む</button></form><p>修正する場合はブラウザで戻って編集してください。</p><a href="/">板一覧</a></body></html>`))
var errorPage = template.Must(template.Must(postFormTemplate.Clone()).New("error").Parse(`<!doctype html><html lang="ja"><head><meta charset="UTF-8"><title>投稿内容の確認</title></head><body><h1>投稿できませんでした</h1><p role="alert">{{.Message}}</p><p>トリップ秘密は必要に応じて再入力してください。</p>{{template "post" .Form}}<a href="/">板一覧</a></body></html>`))

func (s *Server) newPostForm(w http.ResponseWriter, r *http.Request, key string) postForm {
	return postForm{Board: s.slug, Key: key, RequestID: randomToken(), CSRF: formCSRF(w, r, s.key, "oimo_web", "post", s.base.Scheme == "https", s.clock())}
}

// webPost は署名フォームと送信元を検証し、確認を経て共通Submitへ渡す。
func (s *Server) webPost(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(405)
		return
	}
	if !sameOrigin(r, s.base) {
		http.Error(w, "origin denied", 403)
		return
	}
	b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if e != nil {
		http.Error(w, "body too large", 413)
		return
	}
	f, e := compat.ParseForm(b, r.Header.Get("Content-Type"), true)
	if e != nil {
		status := 400
		if e == compat.ErrCharset {
			status = 415
		}
		http.Error(w, "invalid form", status)
		return
	}
	target := s.boardByKey(f["bbs"])
	if target == nil {
		http.NotFound(w, r)
		return
	}
	if !csrfValid(r, f["csrf"], target.key, "oimo_web", "post", target.clock()) {
		http.Error(w, "フォームが無効または期限切れです。板から開き直してください。", 403)
		return
	}
	r.Form = make(url.Values)
	for k, v := range f {
		r.Form.Set(k, v)
	}
	if !requestPattern.MatchString(f["oimo_request_id"]) {
		target.webResult(w, r, "error", "投稿フォームを開き直してください。", "")
		return
	}
	target.submitFields(w, r, f)
}
func (s *Server) renderConfirmation(w http.ResponseWriter, r *http.Request, fields map[string]string, input prepared, token string) {
	safe := map[string]string{}
	for _, key := range []string{"bbs", "key", "subject", "FROM", "mail", "MESSAGE", "oimo_request_id", "csrf"} {
		safe[key] = fields[key]
	}
	renderHTML(w, r, 200, confirmationPage, struct {
		Notice string
		Input  prepared
		Fields map[string]string
		Token  string
	}{notice, input, safe, token})
}

// webResult は成功時に確定レスへ303遷移し、失敗時には秘密以外の入力を保持する。
func (s *Server) webResult(w http.ResponseWriter, r *http.Request, kind, message, link string) {
	w.Header().Set("Cache-Control", "no-store")
	if kind == "posted" || kind == "already" {
		http.Redirect(w, r, link, http.StatusSeeOther)
		return
	}
	name, _, _ := strings.Cut(r.Form.Get("FROM"), "#")
	form := postForm{Board: s.slug, Key: r.Form.Get("key"), Subject: r.Form.Get("subject"), Name: name, Mail: r.Form.Get("mail"), Body: r.Form.Get("MESSAGE"), RequestID: randomToken(), CSRF: r.Form.Get("csrf")}
	renderHTML(w, r, 422, errorPage, struct {
		Message string
		Form    postForm
	}{message, form})
}
func renderHTML(w http.ResponseWriter, r *http.Request, status int, t *template.Template, data any) {
	var b bytes.Buffer
	if e := t.Execute(&b, data); e != nil {
		http.Error(w, "render failed", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	if r.Method != "HEAD" {
		_, _ = w.Write(b.Bytes())
	}
}
