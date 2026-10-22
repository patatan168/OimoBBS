// 通常投稿の提出を、既存の保全・署名ZIP・一回取得へ順に接続する。新しい保存形式は作らない。
package bootstrap

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
)

// validateEvidenceExtractionLocked は副作用前に案件版と必要な権限を検査する。
// 呼出側がrepo.muを保持する。保全済み案件の取得には保全権限を追加要求しない。
func (h *adminHandler) validateEvidenceExtractionLocked(s adminauth.Session, id domain.ID, etag string) (disclosure.Case, error) {
	if e := h.repo.authorizeEvidence(s, "evidence.manage", domain.ID{}, true); e != nil {
		return disclosure.Case{}, e
	}
	c, e := h.repo.evidenceCases.Get(id)
	if e != nil {
		return c, e
	}
	if e = h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
		var denied *adminFailure
		if errors.As(e, &denied) && (denied.code == "BOARD_SCOPE_DENIED" || denied.code == "BOARD_SCOPE_REQUIRED") {
			return c, &adminFailure{status: 404, code: "EVIDENCE_NOT_FOUND"}
		}
		return c, e
	}
	if _, e = h.repo.evidenceCases.AuthorizeState(id, etag, time.Now()); e != nil {
		return c, e
	}
	if c.Rejected != nil || c.HTTP != nil && c.HTTP.Unbound || c.State != "draft" && c.State != "active" && c.State != "partial" {
		return c, &adminFailure{status: 409, code: "EVIDENCE_EXTRACT_STATE"}
	}
	if c.State == "draft" {
		e = h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true)
	}
	return c, e
}

// extractEvidence は保全前なら先にコピーし、同じ理由で全項目を生成して直ちにZIPを送る。
// 各段階は既存の監査へ保存し、失敗時は進んだ段階を残して既存画面で再開できる。
func (h *adminHandler) extractEvidence(w http.ResponseWriter, r *http.Request, s adminauth.Session, id domain.ID, input evidenceInput, etag, key string) {
	h.repo.mu.Lock()
	c, e := h.validateEvidenceExtractionLocked(s, id, etag)
	var release func()
	if e == nil {
		release, e = h.repo.reserveEvidence()
	}
	holdKey := h.repo.evidenceCases.IDFor(s.Admin, "extract-hold:"+key).String()
	needsHold := c.State == "draft"
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, evidenceError(e))
		return
	}
	defer release()
	if needsHold {
		if e = h.repo.prepareRequiredHoldStorage(r.Context(), s, id, etag, holdKey, input.Reason); e != nil {
			h.failure(w, r, evidenceError(e))
			return
		}
	}
	h.repo.mu.Lock()
	c, e = h.validateEvidenceExtractionLocked(s, id, etag)
	if e == nil && needsHold {
		c, e = h.repo.holdRequiredEvidence(r.Context(), s, c, etag, holdKey, input.Reason)
	}
	var file *os.File
	var export disclosure.Export
	if e == nil {
		c, file, export, e = h.createEvidenceExtractionLocked(r, s, c, key, input)
	}
	h.repo.mu.Unlock()
	if e != nil {
		h.failure(w, r, evidenceError(e))
		return
	}
	h.sendEvidenceZIP(w, r, s, c, file, export)
}

// createEvidenceExtractionLocked は保全の待機後に認可を再検査し、生成・消費を耐久記録する。
func (h *adminHandler) createEvidenceExtractionLocked(r *http.Request, s adminauth.Session, c disclosure.Case, key string, input evidenceInput) (disclosure.Case, *os.File, disclosure.Export, error) {
	if e := r.Context().Err(); e != nil {
		return c, nil, disclosure.Export{}, e
	}
	if e := h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
		return c, nil, disclosure.Export{}, e
	}
	exportKey := h.repo.evidenceCases.IDFor(s.Admin, "extract-export:"+key).String()
	downloadKey := h.repo.evidenceCases.IDFor(s.Admin, "extract-download:"+key).String()
	c, v, e := h.repo.generateEvidence(r.Context(), s, c, c.ETag(), exportKey, input.Reason, []string{"connection", "content"}, time.Now())
	if e != nil {
		return c, nil, v, e
	}
	if e = h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true); e != nil {
		return c, nil, v, e
	}
	return h.repo.evidenceCases.Download(c.ID, v.ID, s.Admin, c.ETag(), downloadKey, input.Reason, time.Now())
}

// sendEvidenceZIP は通常取得と直接取得で共通の送信を行い、各片で現在権限・期限を検査する。
func (h *adminHandler) sendEvidenceZIP(w http.ResponseWriter, r *http.Request, s adminauth.Session, c disclosure.Case, file *os.File, v disclosure.Export) {
	defer file.Close()
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="evidence-%s.zip"`, v.ID))
	w.Header().Set("Content-Length", strconv.FormatUint(uint64(v.Bytes), 10))
	w.Header().Set("ETag", c.ETag())
	guarded := &adminCheckedWriter{ResponseWriter: w, check: func() error {
		h.repo.mu.Lock()
		defer h.repo.mu.Unlock()
		e := h.repo.authorizeEvidence(s, "evidence.manage", c.Scope.Board, true)
		current, err := h.repo.evidenceCases.Get(c.ID)
		if e == nil {
			e = err
		}
		at := domain.Time(time.Now().UnixNano())
		if e == nil && (current.State == "closed" || current.State == "releasing" || at >= current.Until || at >= v.Until || at < v.Created) {
			e = disclosure.ErrExpired
		}
		return e
	}}
	buf := make([]byte, 32<<10)
	for {
		if guarded.check() != nil {
			panic(http.ErrAbortHandler)
		}
		n, err := file.Read(buf)
		if n > 0 {
			if _, e := guarded.Write(buf[:n]); e != nil {
				return
			}
		}
		if err == io.EOF {
			return
		}
		if err != nil {
			panic(http.ErrAbortHandler)
		}
	}
}

// evidenceFailureMessage は提出画面で解決できる拒否理由を日本語で示す。
func evidenceFailureMessage(code string) string {
	switch code {
	case "CSRF_REJECTED":
		return "画面を開き直して、もう一度操作してください。再認証や再ログイン後は古い画面のボタンを使えません。"
	case "EVIDENCE_HOLD_REQUIRED":
		return "この案件はまだ保全されていません。提出用ログの「ZIPを作成してダウンロード」を使うと、保全から続けて取得できます。"
	case "EVIDENCE_EXTRACT_STATE", "EVIDENCE_CONFLICT":
		return "この案件は処理途中、または別の操作が進んでいます。最新の状態を確認し、表示された再開操作から、保全・ZIP作成の続きを実行してください。"
	case "EVIDENCE_EXPIRED":
		return "案件・提出ZIPの期限が切れているか、このZIPは取得済みです。期限内の案件から新しいZIPを作成してください。"
	case "EVIDENCE_SCOPE_LIMIT":
		return "対象期間に保存済みの投稿記録がないか、件数・保存容量の上限を超えています。板・スレッド・期間を確認し、対象を100投稿以内に絞ってください。"
	case "INVALID_EVIDENCE_INPUT", "INVALID_DATE", "INVALID_THREAD", "INVALID_ID":
		return "板・スレッド番号・日時を確認してください。開始は終了より前、終了は現在までの日時で指定してください。"
	case "EVIDENCE_REASON_REQUIRED":
		return "ログを提出する理由を入力してください。"
	case "EVIDENCE_REVISION_CONFLICT":
		return "案件の状態が変わっています。提出用ログを開き直して、最新のボタンから操作してください。"
	}
	return ""
}
