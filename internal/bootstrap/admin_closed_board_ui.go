// 閉鎖した板の設定は参照だけを許可し、保存済みログの管理は継続できるようにする。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
)

// closedBoardSettingsGate は認可済みの設定経路で、閉鎖後の編集URLと古いフォーム送信を止める。
func (h *adminHandler) closedBoardSettingsGate(w http.ResponseWriter, r *http.Request, s adminauth.Session) bool {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	parts := strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
	if !strings.HasPrefix(path, "/boards/") || len(parts) < 2 {
		return false
	}
	switch parts[1] {
	case "settings", "metadata", "reading", "local-rules", "thread-settings", "rules":
	default:
		return false
	}
	var id domain.ID
	if json.Unmarshal([]byte(strconv.Quote(parts[0])), &id) != nil {
		return false
	}
	h.repo.mu.Lock()
	err := h.repo.authorizeAdmin(s, "board_admin", id)
	b := h.repo.posting[id]
	closed := err == nil && b != nil && b.closedAt.Load() != 0
	h.repo.mu.Unlock()
	if !closed {
		return false
	}
	if r.Method != http.MethodGet {
		h.fail(w, r, http.StatusConflict, "BOARD_CLOSED")
		return true
	}
	if !strings.HasPrefix(r.URL.Path, "/api/v1/") && parts[1] != "settings" {
		http.Redirect(w, r, "/boards/"+id.String()+"/settings", http.StatusSeeOther)
		return true
	}
	return false
}
