// 管理用のログインとサイト設定画面。秘密や保存内部型をtemplateへ渡さない。
package bootstrap

import (
	"net/http"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/compat"
	"oimobbs/internal/delivery"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
	"time"
)

type adminPage struct {
	OTPCSRF                                                 string
	OTPEnabled, PasswordDisabled                            bool
	PasskeyCSRF                                             string
	Resources                                               *RuntimeResourceStatus
	OptionalLogs                                            *OptionalLogStatus
	Compression                                             *compat.CompressionCacheStatus
	Delivery                                                *delivery.Status
	Latency                                                 *PostingLatencyStatus
	Capacity                                                *PostingCapacityStatus
	Maintenance                                             *PackMaintenanceStatus
	BackPath                                                string
	ActionPath, ActionLabel                                 string
	Title, Message, CSRF, LogoutCSRF, RequestID, ETag, Name string
	Reauth                                                  bool
	Login, Settings                                         bool
}

var adminTemplate = webui.Template("admin")

func writeAdminPage(w http.ResponseWriter, status int, page adminPage) {
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(status)
	_ = executeAdminTemplate(w, w, adminTemplate, page)
}
func (h *adminHandler) loginPage(w http.ResponseWriter, status int, message string) {
	cookie, csrf, e := h.auth.LoginForm(time.Now())
	if e != nil {
		writeAdminPage(w, 503, adminPage{Title: "現在ログインできません"})
		return
	}
	http.SetCookie(w, h.adminCookie("oimo_admin_login", cookie, 600))
	writeAdminPage(w, status, adminPage{Title: "管理者ログイン", Login: true, CSRF: csrf, Message: message})
}
func (h *adminHandler) settingsPage(w http.ResponseWriter, site AdminSite, s adminauth.Session) {
	writeAdminPage(w, 200, adminPage{Title: "サイト設定", Settings: true, Name: site.Name, ETag: site.ETag(), RequestID: domain.NewID().String(), CSRF: s.CSRF("/api/v1/site"), LogoutCSRF: s.CSRF("/logout")})
}
