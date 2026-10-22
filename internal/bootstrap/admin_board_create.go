// 管理画面の板追加を既存の復旧可能な作成処理へ接続する。
package bootstrap

import (
	"errors"
	"net/http"

	"oimobbs/internal/adminauth"
)

// createBoard はサイト管理者の入力とCSRFを検査し、追加後の設定画面へ移動する。
func (h *adminHandler) createBoard(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	fields, e := adminForm(w, r, 8192, "csrf", "key", "name", "posting_mode")
	if e != nil {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	if !s.CheckCSRF("/boards", fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	h.repo.mu.Lock()
	e = h.repo.authorizeAccountChange(s)
	var info BoardInfo
	policy := fields.Get("posting_mode")
	if policy == "" && !fields.Has("posting_mode") {
		policy = "anyone"
	}
	if e == nil && (!validBoardKey(fields.Get("key")) || !validName(fields.Get("name")) || policy != "anyone" && policy != "cap_only") {
		h.repo.mu.Unlock()
		writeAdminBoards(w, 400, adminBoardsPage{CanCreate: true, CreateReady: true, Values: fields, Message: "板キー・表示名・板の種類を確認してください。"})
		return
	}
	if e == nil {
		info, e = h.repo.createBoardWithPolicyLocked(r.Context(), fields.Get("key"), fields.Get("name"), &s.Admin, policy)
	}
	h.repo.mu.Unlock()
	if e != nil {
		var f *adminFailure
		if errors.As(e, &f) && f.status == 409 {
			message := "板の追加上限に達しました。"
			if f.code == "BOARD_KEY_EXISTS" {
				message = "この板キーは別の表示名で使用されています。"
			}
			if f.code == "BOARD_POLICY_EXISTS" {
				message = "この板キーは別の投稿条件で使用されています。既存板の設定画面を確認してください。"
			}
			writeAdminBoards(w, 409, adminBoardsPage{CanCreate: true, CreateReady: true, Values: fields, Message: message})
			return
		}
		h.failure(w, r, e)
		return
	}
	http.Redirect(w, r, "/boards/"+info.ID.String()+"/settings", http.StatusSeeOther)
}
