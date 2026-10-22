// 未受理・閲覧ログの保全と署名ZIPの取得を一つの操作へまとめる。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"time"
)

// extractOtherEvidence は対象種別を検査し、既存の保全・出力・一回取得へ順に接続する。
func (h *adminHandler) extractOtherEvidence(w http.ResponseWriter, r *http.Request, s adminauth.Session, id domain.ID, input evidenceInput, etag, key string, httpOnly bool) {
	minimum := uint32(54)
	if httpOnly {
		minimum = 56
	}
	if e := h.repo.prepareRejectedEvidenceAction(r.Context(), s, id, "evidence.manage", []string{"connection"}, minimum); e != nil {
		h.failure(w, r, evidenceError(e))
		return
	}
	h.repo.mu.Lock()
	current, inspectErr := h.repo.evidenceCases.Get(id)
	needsHTTPHold := httpOnly && (current.HTTP == nil || current.HTTP.State == "preparing")
	h.repo.mu.Unlock()
	if inspectErr != nil {
		h.failure(w, r, evidenceError(inspectErr))
		return
	}
	if needsHTTPHold {
		if _, e := h.repo.enableStorageReader(r.Context(), 57, "http_case_hold_enable"); e != nil {
			h.failure(w, r, e)
			return
		}
		if e := h.repo.ensureOptionalHoldStorage(r.Context()); e != nil {
			h.failure(w, r, evidenceError(e))
			return
		}
	}
	h.repo.mu.Lock()
	c, e := h.repo.evidenceCases.Get(id)
	if e == nil {
		e = h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true)
	}
	if e == nil {
		_, e = h.repo.evidenceCases.AuthorizeState(id, etag, time.Now())
	}
	if e == nil && (len(c.Items) > 0 || c.Required != nil || c.State != "draft" && c.State != "preparing" && c.State != "active" && c.State != "partial" || httpOnly && (c.Rejected != nil || c.HTTP != nil && !c.HTTP.Unbound || c.Scope.Thread != 0) || !httpOnly && c.HTTP != nil) {
		e = disclosure.ErrConflict
	}
	var release func()
	if e == nil {
		release, e = h.repo.reserveEvidence()
	}
	if e != nil {
		h.repo.mu.Unlock()
		h.failure(w, r, concealRejectedCaseDenial(evidenceError(e)))
		return
	}
	defer release()
	holdKey := h.repo.evidenceCases.IDFor(s.Admin, "extract-other-hold:"+key).String()
	if httpOnly {
		if c.HTTP == nil || c.HTTP.State == "preparing" {
			c, e = h.repo.holdOptionalHTTP(r.Context(), s, c, c.ETag(), holdKey, input.Reason, true)
		}
	} else if c.Rejected == nil || c.Rejected.State == "preparing" {
		c, e = h.repo.holdRejectedEvidence(r.Context(), s, c, c.ETag(), holdKey, input.Reason)
	}
	var v disclosure.Export
	exportKey := h.repo.evidenceCases.IDFor(s.Admin, "extract-other-export:"+key).String()
	if e == nil {
		if httpOnly {
			c, v, e = h.repo.generateEvidence(r.Context(), s, c, c.ETag(), exportKey, input.Reason, []string{"connection"}, time.Now())
		} else {
			c, v, e = h.repo.generateRejectedEvidence(r.Context(), s, c, c.ETag(), exportKey, input.Reason, []string{"connection"})
		}
	}
	if e == nil {
		e = h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true)
	}
	if e != nil {
		h.repo.mu.Unlock()
		h.failure(w, r, evidenceError(e))
		return
	}
	downloadKey := h.repo.evidenceCases.IDFor(s.Admin, "extract-other-download:"+key).String()
	c, file, v, e := h.repo.evidenceCases.Download(c.ID, v.ID, s.Admin, c.ETag(), downloadKey, input.Reason, time.Now())
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, evidenceError(e))
		return
	}
	h.sendEvidenceZIP(w, r, s, c, file, v)
}
