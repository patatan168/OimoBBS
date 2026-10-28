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
		if _, ok := auditLabels[q.Action]; !ok {
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
	queryStart := time.Now()
	page, e := h.repo.auditPageSnapshot(r.Context(), s, q, cursor, r.Context().Value(adminAssetCheckContextKey{}) != true)
	if timing, ok := r.Context().Value(adminTimingKey{}).(*adminResponseTiming); ok {
		timing.auditMeasured = true
		timing.auditQuery = time.Since(queryStart)
	}
	if e != nil {
		h.auditFailure(w, r, e)
		return
	}
	if r.URL.Path == "/api/v1/audit" {
		adminJSON(w, 200, map[string]any{"data": page, "request_id": domain.NewID()})
		return
	}
	if renderAdminAssetOnly(w, r, auditTemplate, auditView{}) {
		return
	}
	viewStart := time.Now()
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
	actors, e := h.repo.auditActorOptions(s, page)
	if e != nil {
		h.failure(w, r, e)
		return
	}
	rows := make([]auditRow, 0, len(page.Entries))
	for _, entry := range page.Entries {
		row := newAuditRow(entry, boards)
		for _, actor := range actors {
			if entry.ActorID != nil && actor.Code == entry.ActorID.String() {
				if actor.Label != "管理者："+actor.Code && actor.Label != "CAP："+actor.Code {
					row.ActorLabel = actor.Label
				}
				break
			}
		}
		rows = append(rows, row)
	}
	var buf bytes.Buffer
	if e = executeAdminTemplate(w, &buf, auditTemplate, auditView{Page: page, Values: values, Options: options, Rows: rows, Next: next, Boards: boards, Actors: actors, FromLabel: auditTimeLabel(page.From), ToLabel: auditTimeLabel(page.To)}); e != nil {
		http.Error(w, "画面を表示できません。", 500)
		return
	}
	if timing, ok := r.Context().Value(adminTimingKey{}).(*adminResponseTiming); ok {
		timing.auditView = time.Since(viewStart)
	}
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.WriteHeader(200)
	_, _ = w.Write(buf.Bytes())
}

var auditLabels = map[string]string{
	"software_update_request":           "ソフトウェア更新を要求",
	"board_categories_update":           "板のカテゴリー・並び順を変更",
	"administrator_password_changed":    "自分のパスワードを変更",
	"administrator_passkey_register":    "パスキーを登録",
	"administrator_passkey_remove":      "パスキーを削除",
	"administrator_passkey_login":       "パスキーでログイン",
	"administrator_passkey_reauth":      "パスキーで再認証",
	"administrator_otp_register_finish": "認証アプリを登録",
	"administrator_otp_remove":          "認証アプリを解除",
	"administrator_otp_policy":          "ログイン方法の設定を変更",
	"administrator_otp_used":            "認証アプリのコードを使用",
	"administrator_update":              "管理者の登録情報・認証情報を変更",
	"anonymous_mode_update":             "匿名Cookieの利用条件を変更",
	"auto_report_stop":                  "自動検出による投稿規制を登録",
	"case_completion_tail_enable":       "保存形式を更新：完了案件の記録保持",
	"case_export_cleanup_enable":        "保存形式を更新：提出用ファイルの自動整理",
	"case_retirement_register":          "提出用ログの案件整理を登録",
	"control_expiry_boundary":           "期限切れデータの整理基準時刻を記録",
	"control_expiry_enable":             "保存形式を更新：期限切れの一時データ整理",
	"control_snapshot_enable":           "保存形式を更新：設定の状態をまとめて保存",
	"expired_records_cleanup":           "期限切れの一時データを整理",
	"local_rules_enable":                "保存形式を更新：板のローカルルール編集",
	"local_rules_update":                "板のローカルルールを変更",
	"network_config":                    "回線分類の設定を変更",
	"network_fetch_failed":              "回線分類データの取得に失敗",
	"network_refresh":                   "回線分類データを更新",
	"posting_policies_enable":           "共通の投稿制限を有効化",
	"reports_interval_enable":           "保存形式を更新：削除依頼の送信間隔制限",
	"report_update":                     "削除依頼・問い合わせの対応内容を更新",
	"required_original_gc_configure":    "原本ログの自動整理を設定",
	"required_original_gc_enable":       "保存形式を更新：原本ログの自動整理",
	"required_original_gc_progress":     "原本ログの自動整理の進捗を記録",
	"storage_pressure_enable":           "保存形式を更新：空き容量に応じた整理",
	"thread_actions_enable":             "保存形式を更新：スレッドの管理操作",
	"thread_audit_transfer_enable":      "保存形式を更新：スレッド操作の記録引継ぎ",
	"thread_body_reclaim_enable":        "保存形式を更新：スレッド本文の保存領域の解放",
	"thread_body_watermark":             "スレッド本文の削除に伴う一覧順序の基準を記録",
	"thread_expiry_enable":              "保存形式を更新：スレッドの保存期限",
	"thread_pack_enable":                "保存形式を更新：スレッドの圧縮保存",

	"global_rules_update": "掲示板全体の投稿規制を変更",
	"waf_update":          "WAF設定変更",
	"cap_create":          "キャップ発行", "cap_revoke": "キャップ資格を無効化", "cap_reset": "キャップ鍵を再発行（旧鍵は無効）", "cap_update": "キャップ条件を変更して再発行",
	"cap_display_enable":     "保存形式を更新：キャップの表示",
	"thread_settings_update": "レス数上限・終了レスの変更", "thread_settings_enable": "保存形式を更新：終了レスの設定",
	"abuse_guard_update": "掲示板全体の荒らし対策変更", "operations_update": "運用設定変更", "reading_access_update": "閲覧制限変更", "admin_reading_reset": "管理画面の閲覧制限解除", "site_name_update": "サイト名変更", "posting_consent_update": "利用規約・Cookieの説明変更", "board_settings_update": "板設定変更", "rule_create": "投稿規制を登録", "rule_revoke": "投稿規制を解除",
	"administrator_create": "管理者登録", "administrator_access_update": "管理権限変更",
	"administrator_bootstrap": "初回管理者登録", "administrator_password_reset": "管理者パスワード再設定", "admission_enable": "投稿間隔制限の有効化", "posting_resources_enable": "投稿受付をサーバー資源に応じて調整", "anonymous_enable": "匿名Cookieの有効化", "anonymous_revoke": "匿名Cookieを個別に利用停止", "anonymous_revoke_all": "発行済みの匿名Cookieをすべて利用停止",
	"board_metadata_update": "板名・キー変更", "board_provisioning": "板作成開始", "board_activated": "板の公開開始", "board_settings_enable": "保存形式を更新：板設定の編集", "denial_rules_enable": "保存形式を更新：投稿規制", "other_admin_operation": "詳細未記録の管理操作", "post_evidence_query": "レスの非公開記録照会",
	"cap_command_ban_applied": "CAPによる投稿者規制完了", "cap_command_unban_applied": "CAPによる投稿者規制解除完了", "cap_command_delete_applied": "CAPによるレス削除完了", "cap_command_stop_applied": "CAPによるスレッド停止完了",
	"cap_commands_enable": "保存形式を更新：CAPコマンド", "cap_command_ban": "CAPによる投稿者規制を開始", "cap_command_unban": "CAPによる投稿者規制解除を開始", "cap_command_delete": "CAPによるレス削除を開始", "cap_command_stop": "CAPによるスレッド停止を開始",
}

type auditOption struct{ Code, Label string }
type auditRow struct {
	Entry                                                AuditEntry
	Label, TimeLabel, BoardLabel, PhaseLabel             string
	Description, ActorLabel, ActorShortID, DurationLabel string
	FieldLabels                                          []string
}
type auditView struct {
	Actors             []auditOption
	FromLabel, ToLabel string
	Boards             []boardOption
	Page               AuditPage
	Values             url.Values
	Options            []auditOption
	Rows               []auditRow
	Next               string
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
		message := "検索条件を確認してください。期間は直近180日以内で、開始日時を終了日時より前に指定してください。"
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
