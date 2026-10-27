// 管理画面の更新状態・再起動確認・実行を分け、GETでは更新を開始しない。
package bootstrap

import (
	"bytes"
	"errors"
	"net/http"
	"regexp"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/selfupdate"
	"oimobbs/internal/webui"
)

var updatesTemplate = webui.Template("updates")

type updatesPage struct {
	State               selfupdate.State
	Enabled, Confirm    bool
	Fresh               bool
	CSRF, CheckCSRF     string
	PhaseLabel, Message string
}

func (h *adminHandler) updatesRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method == "GET" && (r.URL.Path == "/updates" || r.URL.Path == "/updates/confirm") {
		h.writeUpdatesPage(w, r, s)
		return
	}
	if r.Method != "POST" || r.URL.Path != "/updates/check" && r.URL.Path != "/updates/apply" {
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	if h.updater == nil {
		h.fail(w, r, 503, "UPDATE_NOT_CONFIGURED")
		return
	}
	names := []string{"csrf"}
	if r.URL.Path == "/updates/apply" {
		names = append(names, "token", "revision", "restart_confirmed")
	}
	fields, err := adminForm(w, r, 4096, names...)
	if err != nil {
		h.fail(w, r, 400, "INVALID_FORM")
		return
	}
	if !s.CheckCSRF(r.URL.Path, fields.Get("csrf")) {
		h.fail(w, r, 403, "CSRF_REJECTED")
		return
	}
	action := "check"
	if r.URL.Path == "/updates/apply" {
		action = "apply"
		if fields.Get("restart_confirmed") != "yes" || len(fields.Get("token")) != 64 || !regexpUpdateRevision.MatchString(fields.Get("revision")) {
			h.fail(w, r, 400, "UPDATE_CONFIRMATION_REQUIRED")
			return
		}
		state, err := h.updater.Request(r.Context(), "status", "", "")
		if err != nil {
			h.fail(w, r, 503, "UPDATE_AGENT_UNAVAILABLE")
			return
		}
		if state.Token != fields.Get("token") || state.LatestRevision != fields.Get("revision") || state.Phase != "ready" && state.Phase != "preparing" && state.Phase != "applying" && state.Phase != "complete" || state.Phase == "ready" && !time.Now().Before(state.Expires) {
			h.fail(w, r, 409, "UPDATE_CONFIRMATION_EXPIRED")
			return
		}
	}
	// socketへの送信直前に世代・権限・再認証を再検査する。失効処理と同じmutexで直列化する。
	h.repo.mu.Lock()
	err = h.repo.currentAdministrator(s)
	if err == nil && action == "apply" {
		err = h.repo.recordSoftwareUpdateLocked(s, fields.Get("token"), fields.Get("revision"))
	}
	if err == nil {
		_, err = h.updater.Request(r.Context(), action, fields.Get("token"), fields.Get("revision"))
	}
	h.repo.mu.Unlock()
	if err != nil {
		if errors.Is(err, selfupdate.ErrConflict) {
			h.fail(w, r, 409, "UPDATE_CONFIRMATION_EXPIRED")
		} else if _, ok := err.(*adminFailure); ok || errors.Is(err, adminauth.ErrSession) {
			h.failure(w, r, err)
		} else {
			h.fail(w, r, 503, "UPDATE_AGENT_UNAVAILABLE")
		}
		return
	}
	http.Redirect(w, r, "/updates", 303)
}

func (h *adminHandler) writeUpdatesPage(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	page := updatesPage{Enabled: h.updater != nil, Confirm: r.URL.Path == "/updates/confirm", Fresh: s.Reauthenticated(time.Now()), CSRF: s.CSRF("/updates/apply"), CheckCSRF: s.CSRF("/updates/check")}
	if h.updater != nil && r.Context().Value(adminAssetCheckContextKey{}) != true {
		state, err := h.updater.Request(r.Context(), "status", "", "")
		if err != nil {
			page.Message = "更新サービスに接続できません。サーバーの稼働状態を確認してください。"
		} else {
			page.State = state
		}
	}
	if page.Confirm && (page.State.Phase != "ready" || !time.Now().Before(page.State.Expires)) {
		page.Confirm = false
		page.Message = "更新対象をもう一度確認してください。確認の有効期限は30分です。"
	}
	page.PhaseLabel = map[string]string{"idle": "未確認", "checking": "最新版を確認中", "ready": "更新あり", "current": "最新版", "preparing": "ビルド・検証中", "applying": "更新・再起動中", "complete": "更新完了", "failed": "要確認"}[page.State.Phase]
	var body bytes.Buffer
	if err := executeAdminTemplate(w, &body, updatesTemplate, page); err != nil {
		h.fail(w, r, 500, "TEMPLATE_FAILED")
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_, _ = w.Write(body.Bytes())
}

// 更新専用パスではブラウザーからブランチ名や実行コマンドを受け取らない。
var regexpUpdateRevision = regexp.MustCompile(`^[a-f0-9]{40}$`)
