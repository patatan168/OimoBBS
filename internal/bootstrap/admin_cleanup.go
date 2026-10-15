// 管理者の明示要求を既存の一件分の削除掃除へ接続する。新しい削除やjobは作成しない。
package bootstrap

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

// redactionCleanupHTML は専用POSTで掃除だけを要求し、通常の削除フォームと入力型を混ぜない。
func (h *adminHandler) redactionCleanupHTML(w http.ResponseWriter, r *http.Request, s adminauth.Session, owner domain.ID, key uint64) {
	if r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	fields, err := adminForm(w, r, 4096, "csrf", "revision", "cleanup_id")
	if err != nil {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	route := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", owner, key)
	if !s.CheckCSRF(route, fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	var id domain.ID
	if id.UnmarshalJSON([]byte(strconv.Quote(fields.Get("cleanup_id")))) != nil || id == (domain.ID{}) {
		h.fail(w, r, 400, "INVALID_DELETION")
		return
	}
	if err := h.repo.retryRedactionCleanup(r.Context(), s, owner, key, id, fields.Get("revision")); err != nil {
		h.failure(w, r, err)
		return
	}
	http.Redirect(w, r, strings.TrimSuffix(r.URL.Path, "/cleanup"), 303)
}

// retryRedactionCleanup は現在の担当/役割/CASを確認し、指定した確定削除だけを掃除する。
// 完了済みは再実行せず、容量不足などで残った作業は成功とせず503を返す。
func (r *Repository) retryRedactionCleanup(ctx context.Context, s adminauth.Session, owner domain.ID, key uint64, deletion domain.ID, etag string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorizeAdmin(s, "moderator", owner); err != nil {
		return err
	}
	b := r.posting[owner]
	if b == nil {
		return &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	_, err := b.worker.Submit(ctx, func() (any, error) {
		if b.stopped {
			return nil, ErrPostingUnavailable
		}
		p := b.threads[key]
		if p == nil {
			return nil, &adminFailure{status: 404, code: "THREAD_NOT_FOUND"}
		}
		seq, _, _, ok := p.RetentionState()
		if !ok {
			return nil, ErrPostingUnavailable
		}
		if etag == "" {
			return nil, &adminFailure{status: 428, code: "REVISION_REQUIRED"}
		}
		if etag != fmt.Sprintf(`"%s:%d:%d"`, owner, key, seq) {
			return nil, &adminFailure{status: 412, code: "REVISION_CONFLICT"}
		}
		return nil, b.retryRedactionCleanup(ctx, key, deletion)
	})
	return err
}

// retryRedactionCleanup は指定した削除の既存進捗を使い、完了済みへの追記を避ける。
func (b *postingBoard) retryRedactionCleanup(ctx context.Context, key uint64, id domain.ID) error {
	record, task, err := b.redactionCleanupTarget(key, id)
	if err != nil {
		return err
	}
	switch record.Kind + ":" + record.Phase {
	case "redact:applied", "redact:cleaning":
	default:
		return &adminFailure{status: 409, code: "CLEANUP_NOT_READY"}
	}
	if task.State == "complete" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.cleanRedaction(key, record, task); err != nil {
		return err
	}
	_, task, err = b.redactionCleanupTarget(key, id)
	if err != nil {
		return err
	}
	if task.State != "complete" {
		return &adminFailure{status: 503, code: "CLEANUP_PENDING"}
	}
	return nil
}

func (b *postingBoard) redactionCleanupTarget(key uint64, id domain.ID) (DeletionRecord, DeletionCopyTask, error) {
	records, tasks, err := deletionHistory(b.deletions[key])
	if err != nil {
		return DeletionRecord{}, DeletionCopyTask{}, err
	}
	var task DeletionCopyTask
	for _, v := range tasks {
		if v.Deletion == id {
			task = v
			break
		}
	}
	for _, record := range records {
		if record.ID == id {
			return record, task, nil
		}
	}
	return DeletionRecord{}, DeletionCopyTask{}, &adminFailure{status: 404, code: "DELETION_NOT_FOUND"}
}
