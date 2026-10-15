// 監査一覧の期間・板・操作者・種別を検査し、読み取り専用APIとHTMLを提供する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/webui"
	"sort"
	"strconv"
	"time"
)

func parseAuditQuery(raw string, now time.Time) (auditQuery, string, error) {
	bad := func() (auditQuery, string, error) {
		return auditQuery{}, "", &adminFailure{status: 400, code: "INVALID_AUDIT_QUERY"}
	}
	if len(raw) > 8192 {
		return bad()
	}
	values, e := url.ParseQuery(raw)
	if e != nil {
		return bad()
	}
	allowed := map[string]bool{"from": true, "to": true, "board": true, "actor": true, "action": true, "limit": true, "cursor": true}
	for k, v := range values {
		if !allowed[k] || len(v) != 1 && k != "board" {
			return bad()
		}
	}
	if cursor, ok := values["cursor"]; ok {
		if len(values) != 1 || cursor[0] == "" {
			return bad()
		}
		return auditQuery{}, cursor[0], nil
	}
	q := auditQuery{To: now, Limit: 50}
	if raw := values.Get("to"); raw != "" {
		q.To, e = time.Parse(time.RFC3339Nano, raw)
		if e != nil {
			return bad()
		}
	}
	q.From = q.To.Add(-24 * time.Hour)
	if raw := values.Get("from"); raw != "" {
		q.From, e = time.Parse(time.RFC3339Nano, raw)
		if e != nil {
			return bad()
		}
	}
	if !q.From.Before(q.To) || q.To.After(now) || q.From.Before(now.Add(-180*24*time.Hour)) {
		return bad()
	}
	if raw := values.Get("limit"); raw != "" {
		q.Limit, e = strconv.Atoi(raw)
		if e != nil || q.Limit < 1 || q.Limit > 200 || strconv.Itoa(q.Limit) != raw {
			return bad()
		}
	}
	seen := map[domain.ID]bool{}
	for _, raw := range values["board"] {
		if raw == "" {
			if len(values["board"]) != 1 {
				return bad()
			}
			continue
		}
		var id domain.ID
		if json.Unmarshal([]byte(strconv.Quote(raw)), &id) != nil || id == (domain.ID{}) || seen[id] {
			return bad()
		}
		seen[id] = true
		q.Boards = append(q.Boards, id)
	}
	if len(q.Boards) == 1 {
		q.Board = q.Boards[0]
		q.Boards = nil
	}
	for key, p := range map[string]*domain.ID{"actor": &q.Actor} {
		if raw := values.Get(key); raw != "" {
			if json.Unmarshal([]byte(strconv.Quote(raw)), p) != nil {
				return bad()
			}
		}
	}
	q.Action = values.Get("action")
	if q.Action != "" {
		if _, ok := auditActions[q.Action]; !ok {
			return bad()
		}
	}
	return q, "", nil
}
func (h *adminHandler) audit(w http.ResponseWriter, r *http.Request, s adminauth.Session) {
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		h.fail(w, r, 405, "METHOD_NOT_ALLOWED")
		return
	}
	q, cursor, e := parseAuditQuery(r.URL.RawQuery, time.Now())
	if e != nil {
		h.auditFailure(w, r, e)
		return
	}
	page, e := h.repo.auditPage(r.Context(), s, q, cursor)
	if e != nil {
		h.auditFailure(w, r, e)
		return
	}
	if r.URL.Path == "/api/v1/audit" {
		adminJSON(w, 200, map[string]any{"data": page, "request_id": domain.NewID()})
		return
	}
	values, _ := url.ParseQuery(r.URL.RawQuery)
	if cursor != "" {
		values = url.Values{}
	}
	values.Set("from", page.From)
	values.Set("to", page.To)
	values.Del("board")
	if page.Board != "" {
		values.Add("board", page.Board)
	}
	for _, id := range page.Boards {
		values.Add("board", id.String())
	}
	values.Set("actor", page.Actor)
	values.Set("action", page.Action)
	values.Set("limit", strconv.Itoa(page.Limit))
	options := []auditOption{}
	for action, label := range auditLabels {
		options = append(options, auditOption{action, label})
	}
	sort.Slice(options, func(i, j int) bool { return options[i].Code < options[j].Code })
	rows := make([]auditRow, 0, len(page.Entries))
	for _, entry := range page.Entries {
		rows = append(rows, auditRow{entry, auditLabels[entry.Action]})
	}
	next := ""
	if page.Next != "" {
		next = "/audit?" + url.Values{"cursor": {page.Next}}.Encode()
	}
	selected := append([]domain.ID{}, page.Boards...)
	if page.Board != "" {
		var id domain.ID
		_ = json.Unmarshal([]byte(strconv.Quote(page.Board)), &id)
		selected = append(selected, id)
	}
	boards, e := h.repo.boardOptions(s, selected)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	var buf bytes.Buffer
	if e = executeAdminTemplate(w, &buf, auditTemplate, auditView{Page: page, Values: values, Options: options, Rows: rows, Next: next, Boards: boards}); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_, _ = w.Write(buf.Bytes())
}

var auditLabels = map[string]string{
	"waf_update": "WAF設定変更",
	"cap_create": "キャップ発行", "cap_revoke": "キャップ資格の削除", "cap_reset": "キャップ鍵の再発行", "cap_update": "キャップ条件を変更して再発行",
	"cap_display_enable":     "キャップ表示形式の更新",
	"thread_settings_update": "レス数上限・終了レスの変更", "thread_settings_enable": "終了レス設定の有効化",
	"abuse_guard_update": "掲示板全体の荒らし対策変更", "operations_update": "運用設定変更", "reading_access_update": "閲覧制限変更", "admin_reading_reset": "管理画面の閲覧制限解除", "site_name_update": "サイト名変更", "board_settings_update": "板設定変更", "rule_create": "拒否規制の登録", "rule_revoke": "拒否規制の解除",
	"administrator_create": "管理者登録", "administrator_access_update": "管理権限変更",
	"administrator_bootstrap": "初回管理者登録", "administrator_password_reset": "管理者パスワード再設定", "admission_enable": "投稿間隔制限の有効化", "anonymous_enable": "匿名Cookieの有効化", "anonymous_revoke": "匿名Cookieの個別失効", "anonymous_revoke_all": "匿名Cookieの全体失効",
	"board_provisioning": "板作成開始", "board_activated": "板の公開開始", "board_settings_enable": "板設定編集の有効化", "denial_rules_enable": "拒否規制の有効化", "other_admin_operation": "その他の管理操作", "post_evidence_query": "レスの非公開記録照会",
	"cap_command_ban_applied": "CAPによるBAN完了", "cap_command_unban_applied": "CAPによるBAN解除完了", "cap_command_delete_applied": "CAPによるレス削除完了", "cap_command_stop_applied": "CAPによるスレッド停止完了",
	"cap_commands_enable": "CAPコマンドの有効化", "cap_command_ban": "CAPによるBAN操作", "cap_command_unban": "CAPによるBAN解除操作", "cap_command_delete": "CAPによるレス削除操作", "cap_command_stop": "CAPによるスレッド停止操作",
}

type auditOption struct{ Code, Label string }
type auditRow struct {
	Entry AuditEntry
	Label string
}
type auditView struct {
	Boards  []boardOption
	Page    AuditPage
	Values  url.Values
	Options []auditOption
	Rows    []auditRow
	Next    string
}

var auditTemplate = webui.Template("audit")

// auditFailure は期限切れcursorと容量制限を、秘密を含まない再取得案内へ変換する。
func (h *adminHandler) auditFailure(w http.ResponseWriter, r *http.Request, e error) {
	if r.URL.Path == "/api/v1/audit" {
		h.failure(w, r, e)
		return
	}
	var f *adminFailure
	if errors.As(e, &f) {
		message := "検索条件を確認してください。期間は直近180日以内、日時はRFC3339形式です。"
		if f.status == 409 {
			message = "一覧の有効期限が切れたか、ページ情報が無効です。条件を指定して再取得してください。"
		}
		if f.status == 503 {
			message = "監査一覧の取得上限に達しました。板や期間を絞るか、10分後に再取得してください。"
		}
		if f.code == "AUDIT_CATCH_UP_PENDING" {
			message = "記録の準備が途中です。再取得すると続きから準備します。"
		}
		if f.code == "AUDIT_INDEX_FULL" {
			message = "監査記録の検索上限に達しました。サーバー管理者による確認が必要です。"
		}
		writeAdminPage(w, f.status, adminPage{Title: "管理操作の記録を取得できません", Message: message, BackPath: "/audit"})
		return
	}
	h.failure(w, r, e)
}
