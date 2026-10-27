// 管理画面から復旧用予約を導入・補充し、共通容量台帳と実割当を照合する。
package bootstrap

import (
	"io"
	"net/http"
	"os"
	"syscall"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/platform"
)

const emergencyReserveRoute = "/api/v1/maintenance/emergency-reserve"

// prepareEmergencyReserve は稼働writerの排他を保持したまま容量台帳の内側で確保する。
// 解放は提供しない。未完了の予約を補充しても通常の30秒回復確認を省略しない。
func (r *Repository) prepareEmergencyReserve(s adminauth.Session, allocate func(*os.File) error) (EmergencyReserveStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.authorizeAdmin(s, "site_admin", domain.ID{}); err != nil {
		return EmergencyReserveStatus{}, err
	}
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	// 未完了状態を先に観測して、補充直後の即時受付再開を防ぐ。
	r.observePostingCapacity()
	status, err := inspectEmergencyReserve(r.cfg.DataDir)
	if err != nil || status.Ready {
		return status, err
	}
	probe := r.packSpace
	if probe == nil {
		probe = platform.Space
	}
	space, err := probe(r.cfg.DataDir)
	if err != nil || !emergencyReserveCapacity(space, status, r.reservedDiskBytes()) {
		return status, &adminFailure{status: 503, code: "RESERVE_CAPACITY_UNAVAILABLE"}
	}
	status, err = writeEmergencyReserve(r.cfg.DataDir, "prepare", 0, status, allocate)
	r.observePostingCapacity()
	return status, err
}

// emergencyReserveRoutes はサイト管理者の明示POSTだけを実割当へ接続する。
func (h *adminHandler) emergencyReserveRoutes(w http.ResponseWriter, req *http.Request, s adminauth.Session) {
	if req.Method != "POST" {
		h.fail(w, req, 405, "METHOD_NOT_ALLOWED")
		return
	}
	api := req.URL.Path == emergencyReserveRoute
	var csrf string
	if api {
		var err error
		csrf, _, err = singleRequestHeader(req.Header, "X-CSRF-Token")
		if err != nil {
			h.fail(w, req, 403, "CSRF_REJECTED")
			return
		}
		// APIは本文を持たない。解放量など未知の操作を受理しない。
		body, err := io.ReadAll(http.MaxBytesReader(w, req.Body, 1))
		if err != nil || len(body) != 0 {
			h.fail(w, req, 400, "INVALID_REQUEST")
			return
		}
	} else {
		fields, err := adminForm(w, req, 4096, "csrf")
		if err != nil {
			h.fail(w, req, 400, "INVALID_FORM")
			return
		}
		csrf = fields.Get("csrf")
	}
	if !s.CheckCSRF(emergencyReserveRoute, csrf) {
		h.fail(w, req, 403, "CSRF_REJECTED")
		return
	}
	status, err := h.repo.prepareEmergencyReserve(s, func(f *os.File) error {
		return syscall.Fallocate(int(f.Fd()), 0, 0, emergencyReserveBytes)
	})
	if err != nil {
		h.failure(w, req, err)
		return
	}
	if api {
		adminJSON(w, 200, map[string]any{"data": status})
		return
	}
	http.Redirect(w, req, "/maintenance", 303)
}
