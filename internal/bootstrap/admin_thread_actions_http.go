// 管理APIと確認画面を同じ先行intent・CAS・再送契約へ接続する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"oimobbs/internal/webui"
)

type threadActionSummary struct {
	ID        domain.ID  `json:"id"`
	Kind      string     `json:"kind"`
	Phase     string     `json:"phase"`
	Revision  domain.U64 `json:"revision"`
	CreatedAt string     `json:"created_at"`
	ExpiresAt string     `json:"thread_expires_at"`
}

// threadActionHTTPValue は未反映の期限終了で版を進めず、日付だけを管理応答へ追加する。
func threadActionHTTPValue(v ThreadActionRecord) threadActionSummary {
	revision := v.Expected + 1
	if v.Phase == "expired" {
		revision = v.Expected
	}
	return threadActionSummary{ID: v.ID, Kind: v.Kind, Phase: v.Phase, Revision: revision, CreatedAt: adminDate(v.Created), ExpiresAt: adminDate(v.Expires)}
}

type threadActionView struct {
	Revision domain.U64            `json:"revision"`
	Expires  string                `json:"expires_at"`
	State    string                `json:"state"`
	Policy   domain.Policy         `json:"policy"`
	Actions  []threadActionSummary `json:"actions"`
	Allowed  []string              `json:"allowed_actions"`
}

func (h *adminHandler) threadActionView(r *http.Request, s adminauth.Session, owner domain.ID, key uint64) (threadActionView, error) {
	h.repo.mu.Lock()
	err := h.repo.authorizeAdmin(s, "moderator", owner)
	b := h.repo.posting[owner]
	account, sessionErr := h.repo.currentAdminSession(s)
	if err == nil {
		err = sessionErr
	}
	allowed := []string{}
	if err == nil && adminRoleRank[account.Role] >= adminRoleRank["moderator"] {
		allowed = append(allowed, "stop")
	}
	if err == nil && adminRoleRank[account.Role] >= adminRoleRank["board_admin"] {
		allowed = append(allowed, "archive", "move_link", "update_policy")
	}
	h.repo.mu.Unlock()
	if err != nil {
		return threadActionView{}, err
	}
	if b == nil {
		return threadActionView{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
	}
	value, err := b.worker.Submit(r.Context(), func() (any, error) {
		p := b.threads[key]
		if p == nil {
			return nil, &adminFailure{status: 404, code: "THREAD_NOT_FOUND"}
		}
		seq, expires, policy, state, err := p.ThreadActionState()
		if err != nil {
			return nil, err
		}
		var rows []ThreadActionRecord
		if adminRoleRank[account.Role] >= adminRoleRank["board_admin"] {
			rows, err = b.threadActions()
			if err != nil {
				return nil, err
			}
		}
		view := threadActionView{Revision: seq, Expires: time.Unix(0, int64(expires)).UTC().Format(time.RFC3339Nano), State: state, Policy: policy, Actions: []threadActionSummary{}, Allowed: allowed}
		if p.PublicExpired(domain.Time(b.clock().UnixNano())) || state == "hidden" {
			view.Allowed = []string{}
		}
		for _, row := range rows {
			if uint64(row.Thread) == key {
				view.Actions = append(view.Actions, threadActionHTTPValue(row))
			}
		}
		sort.Slice(view.Actions, func(i, j int) bool { return view.Actions[i].Revision < view.Actions[j].Revision })
		return view, nil
	})
	if err != nil {
		return threadActionView{}, err
	}
	return value.(threadActionView), nil
}

type threadActionTarget struct {
	Owner domain.ID
	Key   uint64
	Path  string
	API   bool
}

func (h *adminHandler) threadActionRoutes(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	parts := strings.Split(strings.TrimPrefix(path, "/boards/"), "/")
	var owner domain.ID
	if len(parts) != 4 || parts[1] != "threads" || parts[3] != "actions" || json.Unmarshal([]byte(strconv.Quote(parts[0])), &owner) != nil {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	key, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || key == 0 || fmt.Sprint(key) != parts[2] {
		h.fail(w, r, 404, "NOT_FOUND")
		return
	}
	target := threadActionTarget{owner, key, path, strings.HasPrefix(r.URL.Path, "/api/v1/")}
	switch r.Method {
	case "GET":
		h.threadActionGET(w, r, s, target)
	case "POST":
		h.threadActionPOST(w, r, s, target)
	default:
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
	}
}

func (h *adminHandler) threadActionGET(w http.ResponseWriter, r *http.Request, s adminauth.Session, target threadActionTarget) {
	view, err := h.threadActionView(r, s, target.Owner, target.Key)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	etag := fmt.Sprintf(`"%s:%d:%d"`, target.Owner, target.Key, view.Revision)
	w.Header().Set("ETag", etag)
	w.Header().Set("X-CSRF-Token", s.CSRF(r.URL.Path))
	if target.API {
		adminJSON(w, 200, map[string]any{"data": view})
		return
	}
	commands, _ := json.Marshal(view.Policy.Commands)
	fields := url.Values{"commands": {string(commands)}, "csrf": {s.CSRF(target.Path)}, "revision": {etag}, "request_id": {domain.NewID().String()}, "step": {"confirm"}, "kind": {"stop"}, "target": {""}, "slip_mode": {view.Policy.SlipMode}, "require_public_ip": {strconv.FormatBool(view.Policy.RequirePublicIP)}, "require_slip_hash": {strconv.FormatBool(view.Policy.RequireSlipHash)}, "policy_version": {fmt.Sprint(view.Policy.Version)}, "id_mode": {view.Policy.IDMode}, "require_id": {strconv.FormatBool(view.Policy.RequireID)}, "post_limit": {fmt.Sprint(view.Policy.UserPostLimit)}, "dat_limit": {fmt.Sprint(view.Policy.DATUserLimit)}}
	writeThreadActions(w, threadActionsPage{Action: target.Path, Board: target.Owner.String(), Key: target.Key, Values: fields, View: view})
}

func (h *adminHandler) threadActionPOST(w http.ResponseWriter, r *http.Request, s adminauth.Session, target threadActionTarget) {
	var edit AdminThreadAction
	var etag, requestID string
	var err error
	if target.API {
		edit, etag, requestID, err = readThreadActionJSON(w, r, s)
	} else {
		var confirmed bool
		edit, etag, requestID, confirmed, err = h.readThreadActionHTML(w, r, s, target)
		if confirmed {
			return
		}
	}
	if err != nil {
		h.failure(w, r, err)
		return
	}
	saved, err := h.repo.ChangeThread(r.Context(), s, target.Owner, target.Key, edit, etag, requestID)
	if err != nil {
		h.failure(w, r, err)
		return
	}
	summary := threadActionHTTPValue(saved)
	revision := summary.Revision
	w.Header().Set("ETag", fmt.Sprintf(`"%s:%d:%d"`, target.Owner, target.Key, revision))
	if target.API {
		adminJSON(w, 200, map[string]any{"data": summary, "applied": saved.Phase == "applied"})
		return
	}
	writeThreadActions(w, threadActionsPage{Action: target.Path, Board: target.Owner.String(), Key: target.Key, Saved: &summary})
}

func readThreadActionJSON(w http.ResponseWriter, r *http.Request, s adminauth.Session) (edit AdminThreadAction, etag, requestID string, err error) {
	csrf, _, err := singleRequestHeader(r.Header, "X-CSRF-Token")
	if err != nil || !s.CheckCSRF(r.URL.Path, csrf) {
		return edit, "", "", &adminFailure{status: 403, code: "CSRF_REJECTED"}
	}
	etag, exists, err := singleRequestHeader(r.Header, "If-Match")
	if err != nil {
		return edit, "", "", &adminFailure{status: 400, code: "INVALID_REVISION"}
	}
	if !exists {
		return edit, "", "", &adminFailure{status: 428, code: "REVISION_REQUIRED"}
	}
	requestID, _, err = singleRequestHeader(r.Header, "Idempotency-Key")
	if err != nil {
		return edit, "", "", &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if !threadActionJSONType(r.Header) {
		return edit, "", "", &adminFailure{status: 415, code: "JSON_REQUIRED"}
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 32<<10))
	if err != nil {
		return edit, "", "", &adminFailure{status: 413, code: "BODY_TOO_LARGE"}
	}
	if strictjson.Decode(raw, &edit) != nil {
		return edit, "", "", &adminFailure{status: 400, code: "INVALID_JSON"}
	}
	return edit, etag, requestID, nil
}

func threadActionJSONType(header http.Header) bool {
	content, _, err := singleRequestHeader(header, "Content-Type")
	media, params, e := mime.ParseMediaType(content)
	return err == nil && e == nil && media == "application/json" && (len(params) == 0 || len(params) == 1 && strings.EqualFold(params["charset"], "utf-8"))
}

func (h *adminHandler) readThreadActionHTML(w http.ResponseWriter, r *http.Request, s adminauth.Session, target threadActionTarget) (edit AdminThreadAction, etag, requestID string, confirmed bool, err error) {
	fields, err := adminForm(w, r, 32<<10, "csrf", "revision", "request_id", "step", "kind", "target", "policy_version", "id_mode", "require_id", "slip_mode", "require_public_ip", "require_slip_hash", "post_limit", "dat_limit", "commands")
	if err != nil {
		return edit, "", "", false, &adminFailure{status: 400, code: "INVALID_FORM"}
	}
	if !s.CheckCSRF(target.Path, fields.Get("csrf")) {
		return edit, "", "", false, &adminFailure{status: 403, code: "CSRF_REJECTED"}
	}
	edit, err = threadActionForm(fields)
	if err != nil {
		return edit, "", "", false, &adminFailure{status: 422, code: "INVALID_THREAD_ACTION"}
	}
	etag, requestID = fields.Get("revision"), fields.Get("request_id")
	switch fields.Get("step") {
	case "confirm":
		err = h.confirmThreadAction(w, r, s, target, edit, fields)
		return edit, etag, requestID, err == nil, err
	case "apply":
		return edit, etag, requestID, false, nil
	default:
		return edit, "", "", false, &adminFailure{status: 400, code: "INVALID_FORM"}
	}
}

// confirmThreadAction は現在の権限・対象を再検査して、保存を伴わない確認画面を返す。
func (h *adminHandler) confirmThreadAction(w http.ResponseWriter, r *http.Request, s adminauth.Session, target threadActionTarget, edit AdminThreadAction, fields url.Values) error {
	view, err := h.threadActionView(r, s, target.Owner, target.Key)
	if err != nil {
		return err
	}
	if !view.allows(edit.Kind) {
		return &adminFailure{status: 403, code: "PERMISSION_DENIED"}
	}
	if !adminRequestKey.MatchString(fields.Get("request_id")) {
		return &adminFailure{status: 400, code: "INVALID_REQUEST_KEY"}
	}
	if fields.Get("revision") != fmt.Sprintf(`"%s:%d:%d"`, target.Owner, target.Key, view.Revision) {
		return &adminFailure{status: 412, code: "REVISION_CONFLICT"}
	}
	fields.Set("step", "apply")
	writeThreadActions(w, threadActionsPage{Action: target.Path, Board: target.Owner.String(), Key: target.Key, Values: fields, View: view, Confirm: true})
	return nil
}

func threadActionForm(fields url.Values) (AdminThreadAction, error) {
	edit := AdminThreadAction{Kind: fields.Get("kind"), Target: fields.Get("target")}
	if edit.Kind == "update_policy" {
		version, e1 := strconv.ParseUint(fields.Get("policy_version"), 10, 64)
		count, e2 := strconv.ParseUint(fields.Get("post_limit"), 10, 32)
		dat, e3 := strconv.ParseUint(fields.Get("dat_limit"), 10, 64)
		required, e4 := strconv.ParseBool(fields.Get("require_id"))
		if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
			return edit, domain.ErrOperation
		}
		var commandInput struct {
			Commands []string `json:"commands"`
		}
		if strictjson.Decode([]byte(`{"commands":`+fields.Get("commands")+`}`), &commandInput) != nil || commandInput.Commands == nil {
			return edit, domain.ErrOperation
		}
		publicIP, e := strconv.ParseBool(fields.Get("require_public_ip"))
		if e != nil {
			return edit, domain.ErrOperation
		}
		hash, e := strconv.ParseBool(fields.Get("require_slip_hash"))
		if e != nil {
			return edit, domain.ErrOperation
		}
		mode := fields.Get("slip_mode")
		edit.Policy = &domain.Policy{RequireSlipHash: hash, RequirePublicIP: publicIP, Version: domain.U64(version), IDMode: fields.Get("id_mode"), SlipMode: mode, RequireID: required, UserPostLimit: uint32(count), DATUserLimit: domain.U64(dat), Commands: commandInput.Commands}
	}
	return edit, edit.validate()
}

type threadActionsPage struct {
	Action, Board string
	Key           uint64
	Values        url.Values
	View          threadActionView
	Confirm       bool
	Saved         *threadActionSummary
}

var threadActionsTemplate = webui.Template("thread-actions")

// writeThreadActions はHTMLを検証してから成功応答を開始する。
func writeThreadActions(w http.ResponseWriter, page threadActionsPage) {
	var body bytes.Buffer
	if err := executeAdminTemplate(w, &body, threadActionsTemplate, page); err != nil {
		http.Error(w, "管理画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	_, _ = body.WriteTo(w)
}

// ActionLabel は画面の管理操作を日本語の固定文言で表示する。
func (p threadActionsPage) ActionLabel() string {
	kind := p.Values.Get("kind")
	if p.Saved != nil {
		kind = p.Saved.Kind
	}
	return threadActionKindLabel(kind)
}

// KindLabel は履歴の操作種別を固定の日本語で表示する。
func (v threadActionSummary) KindLabel() string { return threadActionKindLabel(v.Kind) }

func threadActionKindLabel(kind string) string {
	switch kind {
	case "stop":
		return "投稿停止"
	case "archive":
		return "アーカイブ"
	case "move_link":
		return "移転先設定"
	case "update_policy":
		return "投稿の表示・上限を変更"
	}
	return "管理変更"
}

// PhaseLabel は保存途中と確定・期限終了を区別する。
func (v threadActionSummary) PhaseLabel() string {
	switch v.Phase {
	case "intent":
		return "再開待ち"
	case "applied":
		return "反映済み"
	case "expired":
		return "保持期限終了のため未反映"
	}
	return "確認が必要"
}

func (v threadActionView) allows(kind string) bool {
	for _, allowed := range v.Allowed {
		if allowed == kind {
			return true
		}
	}
	return false
}

// SlipModes は状態変更画面で選べる公開識別の方式。
func (v threadActionView) SlipModes() []string {
	return []string{"none", "checked", "feature", "verbose", "vvv", "vvvv", "vvvvv", "vvvvvv"}
}

// CanStop は現在の担当範囲で投稿停止を実行できるかを返す。
func (v threadActionView) CanStop() bool { return v.allows("stop") }

// CanManage はアーカイブ・移転先・ポリシー変更の権限を返す。
func (v threadActionView) CanManage() bool { return v.allows("archive") }
