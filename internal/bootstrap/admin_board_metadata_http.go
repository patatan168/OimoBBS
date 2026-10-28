// 板名・公開キーの編集フォームを、サイト管理者の認可・再認証・CSRFへ接続する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

func (h *adminHandler) boardMetadata(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/boards/"), "/")
	var id domain.ID
	if len(parts) != 2 || parts[1] != "metadata" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &id) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	h.repo.mu.Lock()
	err := h.repo.currentAdministrator(s)
	var view adminBoardMetadata
	if err == nil {
		view, err = h.repo.boardMetadataLocked(id)
	}
	h.repo.mu.Unlock()
	if err != nil {
		h.failure(w, r, err)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	fields := url.Values{"key": {view.Key}, "name": {view.Name}, "csrf": {s.CSRF(r.URL.Path)}, "revision": {view.ETag}, "request_id": {domain.NewID().String()}}
	status, message := 200, ""
	if r.Method == "POST" {
		fields, err = adminForm(w, r, 8192, "csrf", "key", "name", "revision", "request_id")
		if err != nil {
			h.fail(w, r, 400, "INVALID_FORM")
			return
		}
		if !s.CheckCSRF(r.URL.Path, fields.Get("csrf")) {
			h.fail(w, r, 403, "CSRF_REJECTED")
			return
		}
		err = h.repo.updateBoardMetadata(r.Context(), s, id, fields)
		if err == nil {
			http.Redirect(w, r, "/boards/"+id.String()+"/settings", 303)
			return
		}
		var failure *adminFailure
		if !errors.As(err, &failure) || failure.status != 422 && failure.code != "BOARD_KEY_EXISTS" {
			h.failure(w, r, err)
			return
		}
		status = failure.status
		message = "板キーと表示名を確認してください。"
		if failure.code == "BOARD_KEY_EXISTS" {
			message = "この板キーは別の板、または別の板の旧キーとして使用されています。"
		}
		if failure.code == "BOARD_ALIAS_LIMIT" {
			message = "旧キーの保持上限（64件）に達しているため、新しいキーへ変更できません。板名の変更と旧キーへの切り替えはできます。"
		}
	}
	writeAdminBoards(w, status, adminBoardsPage{Metadata: true, Name: view.Name, Action: r.URL.Path, Values: fields, Message: message, Aliases: view.Aliases, CreateReady: s.Reauthenticated(time.Now())})
}
