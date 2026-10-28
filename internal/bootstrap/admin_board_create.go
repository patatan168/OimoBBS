// 管理画面の板追加を既存の復旧可能な作成処理へ接続する。
package bootstrap

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"oimobbs/internal/adminauth"
)

// newBoard は追加専用画面を表示し、再認証後も同じ画面へ戻す。
func (h *adminHandler) newBoard(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method != "GET" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	h.repo.mu.Lock()
	err := h.repo.currentAdministrator(s)
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	writeAdminBoards(w, 200, adminBoardsPage{Creating: true, CanCreate: true, CreateReady: s.Reauthenticated(time.Now()), PublicURL: h.repo.cfg.Public.BaseURL, Values: url.Values{"csrf": {s.CSRF("/boards")}}})
}

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
		message := "投稿できる人を選択してください。"
		if !validName(fields.Get("name")) {
			message = "板の名前は、空欄や制御文字を含めず128文字以内で入力してください。"
		}
		if !validBoardKey(fields.Get("key")) {
			message = "板キーは英小文字で始まる英数字・下線で32文字以内です。test・web・adminは使えません。"
		}
		writeAdminBoards(w, 400, adminBoardsPage{Creating: true, CanCreate: true, CreateReady: true, PublicURL: h.repo.cfg.Public.BaseURL, Values: fields, Message: message})
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
				message = "この板キーは既存の板、または旧URLとして使用されています。別のキーを指定してください。"
			}
			if f.code == "BOARD_POLICY_EXISTS" {
				message = "この板キーは別の投稿条件で使用されています。既存板の設定画面を確認してください。"
			}
			writeAdminBoards(w, 409, adminBoardsPage{Creating: true, CanCreate: true, CreateReady: true, PublicURL: h.repo.cfg.Public.BaseURL, Values: fields, Message: message})
			return
		}
		h.failure(w, r, e)
		return
	}
	http.Redirect(w, r, "/boards/"+info.ID.String()+"/settings", http.StatusSeeOther)
}
