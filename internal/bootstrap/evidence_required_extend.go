// 管理延長HTTPを必須元の先行承認/現在参照/実セッション再認可へ接続する。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// requiredCaseExtensionRequest は必須元の新延長または同じ署名承認の再送を選ぶ。
func requiredCaseExtensionRequest(c disclosure.Case, actor domain.ID, until domain.Time) bool {
	x := c.RequiredExtension
	if x != nil && (x.State == "pending" || x.Until == until && x.Actor == actor) {
		return true
	}
	if c.Required != nil {
		return c.Required.Released == nil && (c.State == "preparing" || c.State == "partial")
	}
	return c.State == "preparing" || c.State == "partial"
}

// extendRequiredEvidenceCase は案件/lifecycle排他下で既存承認再送を優先し、元待ち後に実認可を検査する。
func (r *Repository) extendRequiredEvidenceCase(request *http.Request, s adminauth.Session, c disclosure.Case, etag, key, purpose string, until domain.Time) (disclosure.Case, error) {
	replay, found, e := r.evidenceCases.Replay(c.ID, s.Admin, "required_extend_intent", etag, key, struct {
		Purpose string      `json:"purpose"`
		Until   domain.Time `json:"hold_until_ns"`
	}{purpose, until})
	if e != nil {
		return replay, e
	}
	if found {
		return r.replayRequiredExtensionRequest(request, s, c, etag, key, purpose, until)
	}
	if requiredExtensionReplayCandidate(c, s.Admin, until) {
		return r.replayRequiredExtensionRequest(request, s, c, etag, key, purpose, until)
	}
	current, e := r.authorizeRequiredExtensionInput(c, etag, until)
	if e != nil {
		return current, e
	}
	c = current
	b := r.posting[c.Scope.Board]
	if b == nil {
		return c, store.ErrIncomplete
	}
	if b.requiredHolds == nil {
		return c, store.ErrIncomplete
	}
	source, found, e := r.lookupRequiredExtensionSource(request, s, c, b)
	if e != nil {
		return c, e
	}
	if !found {
		return c, store.ErrIncomplete
	}
	return r.prepareRequiredExtensionRequest(request, s, c, source, etag, key, purpose, until)
}

// authorizeRequiredExtensionInput は元照合/reader先行保存より前に要求CASと期限を検査する。
func (r *Repository) authorizeRequiredExtensionInput(c disclosure.Case, etag string, until domain.Time) (disclosure.Case, error) {
	current, e := r.evidenceCases.AuthorizeState(c.ID, etag, time.Now())
	if e != nil {
		return current, e
	}
	if until <= current.Until || until > domain.Time(time.Now().Add(180*24*time.Hour).UnixNano()) {
		return current, disclosure.ErrInvalid
	}
	return current, nil
}

// requiredExtensionReplayCandidate は現在の先行承認または同じ期限/要求者の確認済み承認を選ぶ。
func requiredExtensionReplayCandidate(c disclosure.Case, actor domain.ID, until domain.Time) bool {
	x := c.RequiredExtension
	return x != nil && (x.State == "pending" || x.Until == until && x.Actor == actor)
}

// replayRequiredExtensionRequest は同じkey/旧CAS/入力の再送だけを現在承認へ束縛する。
func (r *Repository) replayRequiredExtensionRequest(request *http.Request, s adminauth.Session, c disclosure.Case, etag, key, purpose string, until domain.Time) (disclosure.Case, error) {
	current, e := r.evidenceCases.PrepareRequiredExtension(c.ID, s.Admin, etag, key, purpose, until, time.Now())
	if e != nil || current.RequiredExtension.State == "complete" {
		return current, e
	}
	return r.resumeRequiredExtensionRequest(request, s, current)
}

// lookupRequiredExtensionSource は元所有列で現在原本/時計を確認し、復帰後の実セッション/CASと元承認を照合する。
func (r *Repository) lookupRequiredExtensionSource(request *http.Request, s adminauth.Session, c disclosure.Case, b *postingBoard) (requiredTerminalSource, bool, error) {
	var source requiredTerminalSource
	var found bool
	e := r.awaitRequiredHoldOwner(request.Context(), b, func() error {
		var e error
		source, found, e = readTerminalRequiredSource(b.requiredHolds, c.ID)
		if e != nil || !found {
			return e
		}
		if source.Receipt.State != "active" {
			return store.ErrIncomplete
		}
		_, e = b.requiredHolds.Fetch(source.Receipt, b.journals, domain.Time(time.Now().UnixNano()))
		return e
	})
	if e != nil {
		return source, found, e
	}
	if e = r.recheckRequiredHold(request.Context(), s, c, b); e != nil {
		return source, found, e
	}
	if !found && c.Required != nil {
		return source, found, store.ErrCorrupt
	}
	if found {
		e = r.evidenceCases.CheckRequiredRenewal(c, source.Receipt, source.Proof)
	}
	return source, found, e
}

// prepareRequiredExtensionRequest は現在元の参照採用と延長intentを同じ案件行に保存する。
func (r *Repository) prepareRequiredExtensionRequest(request *http.Request, s adminauth.Session, c disclosure.Case, source requiredTerminalSource, etag, key, purpose string, until domain.Time) (disclosure.Case, error) {
	release, e := r.reservePrivateLossBytes(1 << 20)
	if e != nil {
		return c, e
	}
	defer release()
	if e = r.enableRequiredExtensionReaderLocked(); e != nil {
		return c, e
	}
	c, e = r.evidenceCases.PrepareRequiredExtensionWithSource(c.ID, s.Admin, etag, key, purpose, until, time.Now(), &source.Receipt)
	if e != nil {
		return c, e
	}
	return r.resumeRequiredExtensionRequest(request, s, c)
}

// resumeRequiredExtensionRequest は元確認待ち後にも実セッションの担当板/権限/再認証を検査する。
func (r *Repository) resumeRequiredExtensionRequest(request *http.Request, s adminauth.Session, c disclosure.Case) (disclosure.Case, error) {
	recheck := func() error { return r.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true) }
	return r.renewPendingRequiredExtension(request.Context(), c, r.posting[c.Scope.Board], recheck)
}
