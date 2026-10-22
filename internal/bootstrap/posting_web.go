// Web投稿のCSRF発行・検証を永続用途鍵と板ワーカーへ接続する内部API。
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"oimobbs/internal/abuse"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"time"
)

// WebCSRFForm はフォーム発行時だけ使用する。Cookie秘密をHTMLや記録へ含めない。
type WebCSRFForm struct {
	Cookie *http.Cookie `json:"-"`
	Token  string       `json:"csrf"`
}

// IssueWebCSRF は新しいCookieと、スレ立て/返信の種別へ束縛したフォーム値を発行する。
// Cookieを置換したブラウザでは旧フォームと不一致になる。旧ペア自体は寿命まで有効。
// 製品フォーム表示/複数タブでの既存Cookie再利用は未接続。
func (repo *Repository) IssueWebCSRF(ctx context.Context, owner domain.ID, route string) (WebCSRFForm, error) {
	return repo.issueWebCSRF(ctx, owner, route, "")
}

// issueWebCSRF は既存の正規Cookieを再利用し、別タブのフォームを無効化しない。
func (repo *Repository) issueWebCSRF(ctx context.Context, owner domain.ID, route, existing string) (WebCSRFForm, error) {
	b, e := repo.postingOwner(owner)
	if e != nil {
		return WebCSRFForm{}, e
	}
	base, e := parseOrigin(repo.cfg.Public.BaseURL)
	if e != nil {
		return WebCSRFForm{}, e
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		return b.makeWebCSRF(route, existing, base.Scheme == "https")
	})
	if e != nil {
		return WebCSRFForm{}, e
	}
	return value.(WebCSRFForm), nil
}

// makeWebCSRF は所有列内でだけ呼び、停止状態と発行時刻を確認する。保存状態は変更しない。
func (b *postingBoard) makeWebCSRF(route, existing string, secure bool) (WebCSRFForm, error) {
	if b.stopped {
		return WebCSRFForm{}, ErrPostingRequest
	}
	now := b.clock()
	cookie := existing
	if _, e := abuse.IssueWebCSRF(cookie, route, b.csrfKey[:], 6, now); e != nil {
		secret := make([]byte, 32)
		if _, e := rand.Read(secret); e != nil {
			return WebCSRFForm{}, e
		}
		cookie = base64.RawURLEncoding.EncodeToString(secret)
		clear(secret)
	}
	token, e := abuse.IssueWebCSRF(cookie, route, b.csrfKey[:], 6, now)
	if e != nil {
		return WebCSRFForm{}, e
	}
	return WebCSRFForm{Cookie: &http.Cookie{Name: "oimo_web", Value: cookie, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 3600, Expires: now.Add(time.Hour)}, Token: token}, nil
}

// SubmitWebRequest は同一originとCookieを必須とし、UTF-8入力を共通投稿処理へ渡す。
// CSRFは列で待った後の時刻でも再検証し、確認・再送照合より前に拒否する。
func (repo *Repository) SubmitWebRequest(r *http.Request, owner domain.ID, observer *evidence.HTTPObserver) LegacyFormResult {
	result, _ := repo.submitWebRequest(r, owner, observer)
	return result
}

// submitWebRequest は画面再表示のため、解析済み入力を一要求内だけで返す。
func (repo *Repository) submitWebRequest(r *http.Request, owner domain.ID, observer *evidence.HTTPObserver) (result LegacyFormResult, parsed map[string]string) {
	defer func() { annotateOptionalResult(r.Context(), owner, result) }()
	confirm, e := checkPostingRequest(r, repo.cfg.Public.BaseURL, true)
	if e != nil {
		return legacyFailure(e), nil
	}
	anon, e := repo.anonymousRequestCookie(r.Header)
	if e != nil {
		return legacyFailure(e), nil
	}
	cookie, e := singlePostingCookie(r.Header, "oimo_web", 43)
	if e != nil || cookie == "" {
		return legacyFailure(abuse.ErrToken), nil
	}
	base, e := parseOrigin(repo.cfg.Public.BaseURL)
	if e != nil {
		return legacyFailure(e), nil
	}
	capture, e := observer.Begin(r, owner, "web_create", base.Host)
	if e != nil {
		return legacyFailure(e), nil
	}
	body, e := io.ReadAll(r.Body)
	if e != nil {
		return legacyFailure(e), nil
	}
	observation, e := capture.Finish()
	if e != nil {
		return legacyFailure(e), nil
	}
	contentType, _, e := singleRequestHeader(r.Header, "Content-Type")
	if e != nil {
		return legacyFailure(e), nil
	}
	fields, e := compat.ParseForm(body, contentType, true)
	if e != nil {
		return legacyFailure(e), nil
	}
	if fields["key"] != "" {
		observation.Route = "web_reply"
	}
	return repo.submitForm(r.Context(), owner, body, contentType, observation, confirm, cookie, true, anon), fields
}
