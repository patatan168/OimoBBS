// 投稿フォーム・確認・エラー・303応答を、既存の永続投稿入口へ接続する。
package bootstrap

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"oimobbs/internal/abuse"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"oimobbs/internal/webui"
	"strconv"
	"time"
)

type postingPage struct {
	Heading, Message, Board, Key, RequestID, CSRF, Title, Body string
	Input                                                      boardInput
	PostingPolicy                                              string
	Confirmation                                               *ConfirmationChallenge
	Fields                                                     map[string]string
	Retry                                                      bool
	CapOnly                                                    bool
}

var postingPageTemplate = webui.Template("posting")

// WebPostingHandler は一つの解決済み板に束縛する内部HTTPハンドラ。
// 上位ルーターが板の解決を担当する。公開serveや管理経路は登録しない。
func (repo *Repository) WebPostingHandler(owner domain.ID, observer *evidence.HTTPObserver) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postingHeaders(w)
		var denied bool
		w, denied = repo.readingBoardGate(w, r, owner)
		if denied {
			return
		}
		if r.URL.EscapedPath() != "/web/post" {
			writePostingPage(w, 404, postingPage{Heading: "ページが見つかりません"})
			return
		}
		switch r.Method {
		case "GET":
			repo.postingFormPage(w, r, owner)
		case "POST":
			repo.postingResultPage(w, r, owner, observer)
		default:
			w.Header().Set("Allow", "GET, POST")
			writePostingPage(w, 405, postingPage{Heading: "この操作は利用できません"})
		}
	})
}
func postingHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// writePostingPage は出力前にHTMLを構築し、テンプレートへの生HTML注入を許さない。
func writePostingPage(w http.ResponseWriter, status int, p postingPage) {
	var buf bytes.Buffer
	if e := postingPageTemplate.Execute(&buf, p); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
func (repo *Repository) postingFormPage(w http.ResponseWriter, r *http.Request, owner domain.ID) {
	base, e := parseOrigin(repo.cfg.Public.BaseURL)
	if e != nil || (base.Scheme == "https") != (r.TLS != nil) {
		writePostingPage(w, 400, postingPage{Heading: "接続先を確認してください"})
		return
	}
	host, e := parseOrigin(base.Scheme + "://" + r.Host)
	if e != nil || normalizedOrigin(host) != normalizedOrigin(base) {
		writePostingPage(w, 400, postingPage{Heading: "接続先を確認してください"})
		return
	}
	values, e := url.ParseQuery(r.URL.RawQuery)
	if e != nil || len(values["key"]) > 1 || len(values["oimo_cap_only"]) > 1 || values.Has("oimo_cap_only") && values.Get("oimo_cap_only") != "1" {
		writePostingPage(w, 400, postingPage{Heading: "投稿先を確認してください"})
		return
	}
	key := values.Get("key")
	capOnly := values.Get("oimo_cap_only") == "1"
	if capOnly && key != "" {
		writePostingPage(w, 400, postingPage{Heading: "投稿先を確認してください"})
		return
	}
	if key != "" {
		var n uint64
		n, e = strconv.ParseUint(key, 10, 64)
		if e == nil && (n == 0 || fmt.Sprint(n) != key) {
			e = ErrPostingRequest
		}
	}
	if e != nil {
		writePostingPage(w, 400, postingPage{Heading: "投稿先を確認してください"})
		return
	}
	repo.renderEditing(w, r, owner, 200, key, "", "", "", capOnly)
}

// renderEditing は板・スレッド条件を取得し、入力エラー時もCAP専用の指定を保持してフォームを表示する。
func (repo *Repository) renderEditing(w http.ResponseWriter, r *http.Request, owner domain.ID, status int, key, title, body, message string, capOnly bool) {
	b, e := repo.postingOwner(owner)
	if e != nil {
		writePostingPage(w, 503, postingPage{Heading: "投稿を利用できません"})
		return
	}
	existing, e := singlePostingCookie(r.Header, "oimo_web", 43)
	if e != nil {
		writePostingPage(w, 400, postingPage{Heading: "Cookieを確認してください"})
		return
	}
	route := "web_create"
	heading := "スレッドを立てる"
	if key != "" {
		route = "web_reply"
		heading = "返信する"
	}
	n, err := strconv.ParseUint(key, 10, 64)
	if key == "" {
		n, err = 0, nil
	}
	base, originError := parseOrigin(repo.cfg.Public.BaseURL)
	if err != nil || originError != nil {
		writePostingPage(w, 400, postingPage{Heading: "投稿先を確認してください"})
		return
	}
	rules, e := repo.submitPostingBatch(r.Context(), b, n, func() (any, error) {
		return b.prepareEditing(n, route, existing, base.Scheme == "https")
	})
	if e != nil {
		if errors.Is(e, errEditingThreadGone) {
			writePostingPage(w, 404, postingPage{Heading: "スレッドが見つかりません"})
		} else {
			writePostingPage(w, 503, postingPage{Heading: "投稿を利用できません"})
		}
		return
	}
	form := rules.(editingForm)
	page := form.page
	if capOnly && key == "" {
		heading = "CAP専用スレッドを立てる"
		if page.PostingPolicy != "disabled" {
			page.PostingPolicy = "cap_only"
		}
	}
	page.Heading, page.Message, page.Board, page.Key = heading, message, b.slug, key
	page.Title, page.Body = title, body
	page.CapOnly = capOnly
	if page.PostingPolicy == "disabled" {
		page.Message = "この板では現在、スレッド作成を停止しています。"
		if key != "" {
			page.Message = "この板では現在、返信を停止しています。"
		}
		writePostingPage(w, status, page)
		return
	}
	csrf := form.csrf
	http.SetCookie(w, csrf.Cookie)
	page.RequestID, page.CSRF = domain.NewID().String(), csrf.Token
	writePostingPage(w, status, page)
}

// postingResultPage は通常投稿の確定を303へ、非公開管理操作の確定を専用案内へ返す。Unknownでは入力/要求IDを変えない。
func (repo *Repository) postingResultPage(w http.ResponseWriter, r *http.Request, owner domain.ID, observer *evidence.HTTPObserver) {
	result, fields := repo.submitWebRequest(r, owner, observer)
	if result.AnonymousCookie != nil {
		http.SetCookie(w, result.AnonymousCookie)
	}
	if result.Confirmation != nil {
		c := result.Confirmation
		base, _ := parseOrigin(repo.cfg.Public.BaseURL)
		http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: c.Token, Path: "/", HttpOnly: true, Secure: base.Scheme == "https", SameSite: http.SameSiteLaxMode, Expires: time.Unix(c.Expires, 0), MaxAge: 600})
		writePostingPage(w, 200, postingPage{Heading: "書き込み確認", Board: fields["bbs"], Confirmation: c, Fields: confirmationFields(fields)})
		return
	}
	if result.Status == store.Durable {
		if result.Management {
			writePostingPage(w, 200, postingPage{Heading: "管理操作を記録しました", Message: "コマンド本文は公開していません。実行内容は管理操作の記録で確認できます。", Board: fields["bbs"]})
			return
		}
		b, e := repo.postingOwner(owner)
		if e != nil {
			writePostingPage(w, 503, postingPage{Heading: "投稿済みです", Message: "表示先を取得できませんでした。"})
			return
		}
		w.Header().Set("Location", fmt.Sprintf("%s/test/read.cgi/%s/%d/%d", repo.cfg.Public.BaseURL, b.slug, result.ThreadKey, result.PostNumber))
		w.WriteHeader(303)
		return
	}
	if result.Status == store.Unknown {
		writePostingPage(w, 503, postingPage{Heading: "投稿結果を確認できません", Message: "同じ内容で結果を確認してください。内容や要求IDを変更しないでください。", Board: fields["bbs"], Retry: true, Fields: confirmationFields(fields)})
		return
	}
	var limited *abuse.RateLimited
	if errors.As(result.Err, &limited) {
		w.Header().Set("Retry-After", fmt.Sprint(limited.RetryAfter))
		heading, message := "投稿間隔を空けてください", "時間を置いて同じ内容を再送してください。"
		writePostingPage(w, 429, postingPage{Heading: heading, Message: message, Board: fields["bbs"], Retry: true, Fields: confirmationFields(fields)})
		return
	}
	if errors.Is(result.Err, errReadingDenied) {
		threadError(w, r, 403, "この接続元からの閲覧・投稿は許可されていません。")
		return
	}
	if message, status := networkAccessMessage(result.Err); message != "" {
		writePostingPage(w, status, postingPage{Heading: "接続元の制限", Message: message, Board: fields["bbs"], Retry: true, Fields: confirmationFields(fields)})
		return
	}
	status := 503
	if errors.Is(result.Err, ErrCapCommand) {
		repo.renderEditing(w, r, owner, 422, fields["key"], fields["subject"], "", "CAP管理コマンドを確認してください。例：>>1 !ban 30m、>>1 !delete、>>1 !unban、>>1 !stop。対象レスは同じスレッドから一件指定します。", false)
		return
	}
	if errors.Is(result.Err, ErrAutoReportDisabled) {
		writePostingPage(w, 403, postingPage{Heading: "通報できません", Message: "この板の通報機能は現在無効です。", Board: fields["bbs"]})
		return
	}
	if errors.Is(result.Err, ErrAutoReportInput) {
		repo.renderEditing(w, r, owner, 422, fields["key"], fields["subject"], fields["MESSAGE"], "対象レスを一件指定してください。例：>>15 !report 広告の連投。改行も使え、理由は任意です。通報受付では「対象URL：対象レス一件のURL」を使ってください。理由は任意です。", fields["oimo_cap_only"] == "1")
		return
	}
	if errors.Is(result.Err, ErrCap) {
		writePostingPage(w, 403, postingPage{Heading: "投稿できません", Message: "キャップの資格・担当板・有効期限を確認してください。"})
		return
	}
	if errors.Is(result.Err, ErrPostingDenied) {
		writePostingPage(w, 403, postingPage{Heading: "投稿が規制されています", Message: "現在、この投稿は規制されています。", Board: fields["bbs"], Retry: true, Fields: confirmationFields(fields)})
		return
	}
	if errors.Is(result.Err, ErrPostingDisabled) {
		writePostingPage(w, 403, postingPage{Heading: "投稿を停止しています", Message: "この板では現在、この投稿操作を停止しています。", Board: fields["bbs"], Retry: true, Fields: confirmationFields(fields)})
		return
	}
	if errors.Is(result.Err, postinput.ErrInput) || errors.Is(result.Err, postinput.ErrUnsupported) {
		status = 422
	}
	if errors.Is(result.Err, compat.ErrForm) {
		status = 400
	}
	if errors.Is(result.Err, abuse.ErrToken) || errors.Is(result.Err, ErrPostingRequest) {
		status = 403
	}
	if errors.Is(result.Err, compat.ErrCharset) {
		status = 415
	}
	if errors.Is(result.Err, evidence.ErrObservedBodyTooLarge) {
		status = 413
	}
	if errors.Is(result.Err, ErrPostingCapacity) {
		w.Header().Set("Retry-After", "30")
		writePostingPage(w, 503, postingPage{Heading: "投稿を一時停止しています", Message: "保存容量の回復を待っています。時間を置いて同じ内容で再送してください。", Board: fields["bbs"], Retry: fields != nil, Fields: confirmationFields(fields)})
		return
	}
	if status == 503 && fields != nil {
		writePostingPage(w, 503, postingPage{Heading: "投稿を利用できません", Message: "時間を置いて同じ内容で結果を確認してください。", Board: fields["bbs"], Retry: true, Fields: confirmationFields(fields)})
		return
	}
	if status != 422 || fields == nil {
		writePostingPage(w, status, postingPage{Heading: "投稿できませんでした", Message: "投稿フォームを開き直してください。"})
		return
	}
	repo.renderEditing(w, r, owner, status, fields["key"], fields["subject"], fields["MESSAGE"], "入力内容を確認してください。名前・メールとトリップ秘密は必要に応じて再入力してください。", fields["oimo_cap_only"] == "1")
}

// confirmationFields は承認の再送に必要な値だけを一時HTMLへ渡す。秘密はhidden以外へ表示しない。
func confirmationFields(fields map[string]string) map[string]string {
	out := map[string]string{}
	for _, key := range []string{"bbs", "key", "FROM", "mail", "subject", "MESSAGE", "csrf", "oimo_request_id", "oimo_cap_only"} {
		if v, ok := fields[key]; ok {
			out[key] = v
		}
	}
	return out
}
