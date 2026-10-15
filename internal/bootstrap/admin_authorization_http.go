// HTML・APIの担当範囲を経路から先に検査し、存在やフォーム情報を権限外へ出さない。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"strconv"
	"strings"
)

func (h *adminHandler) authorizeRoute(s adminauth.Session, r *http.Request) error {
	h.repo.mu.Lock()
	defer h.repo.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	if path == "/reports" || strings.HasPrefix(path, "/reports/") {
		_, err := h.repo.privateReportAdministrator(s)
		return err
	}
	if path == "/auto-reports" || strings.HasPrefix(path, "/auto-reports/") {
		a, e := h.repo.currentAdminSession(s)
		if e != nil {
			return e
		}
		if adminRoleRank[a.Role] < 2 {
			return &adminFailure{status: 403, code: "PERMISSION_DENIED"}
		}
		return nil
	}
	if path == "/evidence" || strings.HasPrefix(path, "/evidence/") {
		_, e := h.repo.currentAdminSession(s)
		return e
	}
	if path == "/caps" || strings.HasPrefix(path, "/caps/") {
		return h.repo.authorizeCap(s, nil)
	}
	if path == "/manual" || path == "/logout" || path == "/reauth" {
		_, e := h.repo.currentAdminSession(s)
		return e
	}
	if path == "/boards" && r.Method != "GET" {
		return h.repo.authorizeAccountChange(s)
	}
	if path == "/boards" || path == "/audit" {
		a, e := h.repo.currentAdminSession(s)
		if e != nil {
			return e
		}
		if adminRoleRank[a.Role] < adminRoleRank["board_admin"] {
			return &adminFailure{status: 403, code: "PERMISSION_DENIED"}
		}
		return nil
	}
	if strings.HasPrefix(path, "/boards/") {
		parts := strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
		var owner domain.ID
		if len(parts) < 2 || json.Unmarshal([]byte(strconv.Quote(parts[0])), &owner) != nil {
			return &adminFailure{status: 400, code: "INVALID_BOARD"}
		}
		if _, _, _, ok := adminPostsPath(path); ok {
			return h.repo.authorizeAdmin(s, "moderator", owner)
		}
		role := "board_admin"
		if strings.HasSuffix(path, "/moderation") || strings.HasSuffix(path, "/moderation/cleanup") || strings.HasSuffix(path, "/actions") {
			role = "moderator"
		}
		return h.repo.authorizeAdmin(s, role, owner)
	}
	return h.repo.authorizeAdmin(s, "site_admin", domain.ID{})
}
