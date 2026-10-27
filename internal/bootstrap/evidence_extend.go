// 案件延長を原本回収と直列化し、元待ちと同じく案件mutexを解放/再取得して現在認可を検査する。
package bootstrap

import (
	"net/http"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// extendEvidenceCase は案件mutex下で入り、回収排他の取得中は解放する。
// 署名期限の更新と回収snapshotを同時に進めず、認可/現在版を取り直してから保存する。
func (r *Repository) extendEvidenceCase(request *http.Request, session adminauth.Session, c disclosure.Case, etag, key, purpose string, until domain.Time) (disclosure.Case, error) {
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	if e := r.available(); e != nil {
		return c, e
	}
	if e := request.Context().Err(); e != nil {
		return c, e
	}
	if e := r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true); e != nil {
		return c, e
	}
	current, e := r.evidenceCases.Get(c.ID)
	if e != nil {
		return c, e
	}
	c = current
	return r.extendEvidenceCaseLocked(request, session, c, etag, key, purpose, until)
}

// extendEvidenceCaseLocked は確定再送/コピー済み延長/元予約付き段階延長を現在案件から選ぶ。
// 呼出元はlifecycleと案件排他を保持し、現在認可を検査する。
func (r *Repository) extendEvidenceCaseLocked(request *http.Request, session adminauth.Session, c disclosure.Case, etag, key, purpose string, until domain.Time) (disclosure.Case, error) {
	if requiredCaseExtensionRequest(c, session.Admin, until) {
		return r.extendRequiredEvidenceCase(request, session, c, etag, key, purpose, until)
	}
	var e error
	if c.Extension != nil && (c.Extension.State == "pending" || c.Extension.Until == until && c.Extension.Actor == session.Admin) {
		c, e = r.evidenceCases.PrepareExtension(c.ID, session.Admin, etag, key, purpose, until, time.Now())
		if e != nil || c.Extension.State == "complete" {
			return c, e
		}
		return r.renewPendingExtension(request.Context(), c, r.optionalStore, func() error { return r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true) })
	}
	if c.HTTP == nil || c.HTTP.State == "active" || r.optionalStore == nil {
		return r.evidenceCases.Extend(c.ID, session.Admin, etag, key, purpose, until, time.Now())
	}
	c, e = r.evidenceCases.AuthorizeState(c.ID, etag, time.Now())
	if e != nil {
		return c, e
	}
	at := domain.Time(time.Now().UnixNano())
	if until <= c.Until || until > at+domain.Time(180*24*time.Hour) {
		return c, disclosure.ErrInvalid
	}
	return r.prepareSourceExtension(request, session, c, etag, key, purpose, until)
}

// prepareSourceExtension は元参照取得後に現在認可/CASを確認し、readerとintentを先行保存する。
func (r *Repository) prepareSourceExtension(request *http.Request, session adminauth.Session, c disclosure.Case, etag, key, purpose string, until domain.Time) (disclosure.Case, error) {
	source := r.optionalStore
	receipt, found, e := r.extensionSourceReceipt(request.Context(), c, source)
	if e != nil {
		return c, e
	}
	if e = r.recheckOptionalHold(session, c, source); e != nil {
		return c, e
	}
	if e = request.Context().Err(); e != nil {
		return c, e
	}
	if !found {
		if c.HTTP.Reservation != nil {
			return c, store.ErrIncomplete
		}
		return r.evidenceCases.Extend(c.ID, session.Admin, etag, key, purpose, until, time.Now())
	}
	if receipt.State != "active" {
		return c, store.ErrIncomplete
	}
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	if e = r.enableOptionalExtensionReaderLocked(); e == nil {
		c, e = r.evidenceCases.PrepareExtensionWithSource(c.ID, session.Admin, etag, key, purpose, until, time.Now(), &receipt)
	}
	release()
	if e != nil {
		return c, e
	}
	return r.renewPendingExtension(request.Context(), c, source, func() error { return r.authorizeEvidence(session, "evidence.manage", c.Scope.Board, true) })
}
