// 専ブラの共通投稿URLを本文のbbsで振り分け、確定結果をlegacy HTMLへ変換する。
package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"oimobbs/internal/abuse"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postinput"
	"oimobbs/internal/store"
	"strconv"
	"time"
)

func (repo *Repository) legacyPostingPage(w http.ResponseWriter, r *http.Request, observer *evidence.HTTPObserver, boards []publicBoard) {
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		threadError(w, r, 405, "POSTで送信してください。")
		return
	}
	result, slug := repo.routeLegacyPost(r, observer, boards)
	annotateOptionalResult(r.Context(), domain.ID{}, result)
	if result.AnonymousCookie != nil {
		http.SetCookie(w, result.AnonymousCookie)
	}
	if result.Confirmation != nil {
		c := result.Confirmation
		base, _ := parseOrigin(repo.cfg.Public.BaseURL)
		http.SetCookie(w, &http.Cookie{Name: "oimo_confirm", Value: c.Token, Path: "/", HttpOnly: true, Secure: base.Scheme == "https", SameSite: http.SameSiteLaxMode, Expires: time.Unix(c.Expires, 0), MaxAge: 600})
		notices := []string{}
		if c.NoReprint {
			for _, rule := range reprintNotice() {
				notices = append(notices, rule.Text)
			}
		}
		writeLegacyResult(w, r, 200, "confirm", "内容を確認して再送してください。", "", notices...)
		return
	}
	if result.Status == store.Durable {
		kind, message := "posted", "投稿を受け付けました。"
		if result.Duplicate {
			kind, message = "already", "同一内容を受理済みです。"
		}
		if result.Management {
			message = "管理操作を記録しました。コマンド本文は公開していません。"
			if result.Duplicate {
				message = "同じ管理操作は記録済みです。"
			}
		}
		link := fmt.Sprintf("%s/test/read.cgi/%s/%d/%d", repo.cfg.Public.BaseURL, slug, result.ThreadKey, result.PostNumber)
		writeLegacyResult(w, r, 200, kind, message, link)
		return
	}
	status, message := 503, "結果を確認できません。同じ内容・同じ再送IDで結果を確認してください。"
	switch {
	case errors.Is(result.Err, errReadingDenied):
		status, message = 403, "この接続元からの閲覧・投稿は許可されていません。"
	case errors.Is(result.Err, evidence.ErrObservedBodyTooLarge):
		status, message = 413, "投稿本文が大きすぎます。"
	case errors.Is(result.Err, compat.ErrCharset):
		status, message = 415, "文字コードを確認してください。"
	case errors.Is(result.Err, compat.ErrForm):
		status, message = 400, "フォームを確認してください。"
	case errors.Is(result.Err, ErrPostingCapacity):
		w.Header().Set("Retry-After", "30")
		status, message = 503, "保存容量を確認中のため、新しい投稿を一時停止しています。時間を置いて再送してください。"
	case errors.Is(result.Err, ErrCapCommand):
		status, message = 200, "CAP管理コマンドの構文・対象レスを確認してください。例：>>1 !ban 30m、>>1 !delete。コマンド本文は公開されません。"
	case errors.Is(result.Err, ErrCap):
		status, message = 200, "キャップの資格・担当板・有効期限を確認してください。"
	case errors.Is(result.Err, ErrUnresolvedHost), errors.Is(result.Err, ErrNetworkPermission), errors.Is(result.Err, ErrForeignIP), errors.Is(result.Err, ErrVPNIP), errors.Is(result.Err, ErrNetworkUnavailable):
		message, status = networkAccessMessage(result.Err)
		if status == 403 {
			status = 200
		}
	case errors.Is(result.Err, ErrPostingDenied):
		status, message = 200, "現在、この投稿は規制されています。"
	case errors.Is(result.Err, ErrPostingDisabled):
		status, message = 200, "この板では現在、この投稿操作を停止しています。"
	case errors.Is(result.Err, ErrPostingRequest):
		status, message = 403, "投稿元を確認してください。"
	case errors.Is(result.Err, ErrAutoReportDisabled):
		status, message = 200, "この板の通報機能は現在無効です。"
	case errors.Is(result.Err, ErrAutoReportInput):
		status, message = 200, "通報は通常のスレッドへ「>>レス番号 !report」、通報受付へは「対象URL：対象レス一件のURL」で返信してください。理由は任意です。"
	case errors.Is(result.Err, postinput.ErrInput), errors.Is(result.Err, postinput.ErrUnsupported):
		status, message = 200, "板・スレッドまたは投稿内容を確認してください。"
	}
	var limited *abuse.RateLimited
	if errors.As(result.Err, &limited) {
		status, message = 429, "投稿間隔を空けて同じ内容を再送してください。"
		w.Header().Set("Retry-After", strconv.FormatUint(limited.RetryAfter, 10))
	}
	writeLegacyResult(w, r, status, "error", message, "")
}

// routeLegacyPost は観測・本文上限を先に設定し、queryに頼らず本文だけで板を解決する。
func (repo *Repository) routeLegacyPost(r *http.Request, observer *evidence.HTTPObserver, boards []publicBoard) (LegacyFormResult, string) {
	fail := func(e error) (LegacyFormResult, string) { return legacyFailure(e), "" }
	token, e := checkLegacyRequest(r, repo.cfg.Public.BaseURL)
	if e != nil {
		return fail(e)
	}
	anon, e := repo.anonymousRequestCookie(r.Header)
	if e != nil {
		return fail(e)
	}
	origin, _ := parseOrigin(repo.cfg.Public.BaseURL)
	capture, e := observer.BeginLegacyRouting(r, origin.Host)
	if e != nil {
		return fail(e)
	}
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return fail(e)
	}
	contentType, _, e := singleRequestHeader(r.Header, "Content-Type")
	if e != nil {
		return fail(e)
	}
	fields, e := compat.ParseForm(body, contentType, false)
	if e != nil {
		return fail(e)
	}
	var owner domain.ID
	for _, b := range boards {
		if b.Key == fields["bbs"] {
			owner = b.ID
			break
		}
	}
	if owner == (domain.ID{}) {
		return fail(postinput.ErrInput)
	}
	observation, e := capture.FinishForBoard(owner)
	if e != nil {
		return fail(e)
	}
	return repo.submitForm(r.Context(), owner, body, contentType, observation, token, "", false, anon), fields["bbs"]
}
func writeLegacyResult(w http.ResponseWriter, r *http.Request, status int, kind, message, link string, notices ...string) {
	body, e := compat.PostResult(kind, message, link, notices...)
	if e != nil {
		threadError(w, r, 503, "応答を作成できません。")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=Shift_JIS")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
