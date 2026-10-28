// 確定controlから秘密なし要約を作り、短命の固定一覧とセッション束縛cursorでページ送りする。
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/adminauth"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AuditEntry は管理操作の公開可能な要約。mutation値・要求HMAC・Cookie・規制対象を持たない。
type AuditEntry struct {
	ID        domain.ID        `json:"id"`
	Owner     domain.ID        `json:"owner_id"`
	OwnerKind string           `json:"owner_kind"`
	Board     *domain.ID       `json:"board_id"`
	Sequence  domain.U64       `json:"sequence"`
	Committed string           `json:"committed_at"`
	ActorKind string           `json:"actor_kind"`
	ActorID   *domain.ID       `json:"actor_id"`
	Action    string           `json:"action"`
	Targets   []string         `json:"target_ids"`
	Fields    []string         `json:"fields"`
	Command   *CapCommandAudit `json:"cap_command,omitempty"`
}

// UnmarshalJSON は旧監査のcap_command省略だけを受け入れ、ほかの完全型検査を保つ。
func (v *AuditEntry) UnmarshalJSON(raw []byte) error {
	var fields map[string]json.RawMessage
	if err := strictjson.Decode(raw, &fields); err != nil {
		return err
	}
	if _, ok := fields["cap_command"]; !ok {
		fields["cap_command"] = json.RawMessage("null")
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	type complete AuditEntry
	var decoded complete
	if err := strictjson.Decode(normalized, &decoded); err != nil {
		return err
	}
	*v = AuditEntry(decoded)
	return nil
}

// CapCommandAudit は本文や識別情報を含まない、管理コマンドの対象と完了状態。
type CapCommandAudit struct {
	Thread   domain.U64 `json:"thread_key"`
	Post     uint32     `json:"post_number"`
	Duration string     `json:"duration"`
	Phase    string     `json:"phase"`
}
type auditQuery struct {
	From, To     time.Time
	Board, Actor domain.ID
	Boards       []domain.ID
	Action       string
	Limit        int
}
type auditSnapshot struct {
	query   auditQuery
	rows    []AuditEntry
	expires time.Time
}

// AuditPage は取得時点で固定したページ。next_cursorは10分有効で現在のsessionだけに束縛する。
type AuditPage struct {
	Entries []AuditEntry `json:"entries"`
	From    string       `json:"from"`
	To      string       `json:"to"`
	Total   uint32       `json:"total"`
	Next    string       `json:"next_cursor"`
	Board   string       `json:"board_id"`
	Boards  []domain.ID  `json:"board_ids,omitempty"`
	Actor   string       `json:"actor_id"`
	Action  string       `json:"action"`
	Limit   int          `json:"limit"`
}

var auditActions = map[string][]string{
	"board_metadata_update":   {"board_directory.name", "board_directory.key", "board_directory.aliases"},
	"storage_pressure_enable": {"site.minimum_reader_version"},
	"global_rules_update":     {"global_rules"},
	"waf_update":              {"waf.enabled"},
	"reading_access_update":   {"reading_access"},
	"admin_reading_reset":     {"reading_access.admin.enabled"},
	"cap_commands_enable":     {"site.minimum_reader_version"},
	"cap_command_ban_applied": {"board_rule"}, "cap_command_unban_applied": {"board_rule"}, "cap_command_delete_applied": {"post.visibility"}, "cap_command_stop_applied": {"thread.state"},
	"cap_command_ban": {"board_rule"}, "cap_command_unban": {"board_rule"}, "cap_command_delete": {"post.visibility"}, "cap_command_stop": {"thread.state"},
	"operations_update":              {"operations.maintenance", "operations.reports", "operations.delivery", "operations.cache"},
	"auto_report_stop":               {"board_rule"},
	"post_evidence_query":            {},
	"report_update":                  {"report.state", "report.assignee", "report.answer"},
	"case_retirement_register":       {"site.minimum_reader_version", "case_retirement"},
	"case_export_cleanup_enable":     {"site.minimum_reader_version"},
	"case_completion_tail_enable":    {"site.minimum_reader_version"},
	"required_original_gc_enable":    {"site.minimum_reader_version"},
	"required_original_gc_configure": {"required_gc.originals"},
	"required_original_gc_progress":  {"required_gc.originals"},
	"network_config":                 {"network.config"},
	"network_refresh":                {"network.rows"},
	"network_fetch_failed":           {"network.status"},
	"thread_audit_transfer_enable":   {"site.minimum_reader_version"},
	"thread_body_reclaim_enable":     {"site.minimum_reader_version"},
	"thread_body_watermark":          {"bump_watermark"},
	"thread_actions_enable":          {"site.minimum_reader_version"},
	"cap_display_enable":             {"site.minimum_reader_version"},
	"cap_update":                     {"cap"},
	"cap_reset":                      {"cap"},
	"cap_create":                     {"cap"}, "cap_revoke": {"cap.enabled", "cap.revision"},
	"control_expiry_enable":   {"site.minimum_reader_version"},
	"control_expiry_boundary": {"expiry_watermark"},
	"expired_records_cleanup": {"expired_control_records"},
	"anonymous_mode_update":   {"anon_policy.mode"},
	"thread_expiry_enable":    {"site.minimum_reader_version"},
	"thread_pack_enable":      {"site.minimum_reader_version"},
	"control_snapshot_enable": {"site.minimum_reader_version"},
	"abuse_guard_update":      {"abuse_guard", "global_posting_policy"},
	"local_rules_update":      {"local_rules"}, "local_rules_enable": {"site.minimum_reader_version"},
	"thread_settings_update": {"thread_settings"}, "thread_settings_enable": {"site.minimum_reader_version"},
	"posting_consent_update": {"site.posting_consent", "site.terms_revision"},
	"site_name_update":       {"site.name"}, "board_settings_update": {"board.settings"},
	"rule_create": {"board_rule"}, "rule_revoke": {"board_rule.enabled"},
	"administrator_update": {"administrator.display_name", "administrator.password", "administrator.role", "administrator.board_ids", "administrator.extra_permissions", "administrator.enabled", "administrator.auth_generation"},
	"administrator_create": {"administrator"}, "administrator_access_update": {"administrator.role", "administrator.board_ids", "administrator.extra_permissions", "administrator.enabled", "administrator.auth_generation"},
	"administrator_bootstrap": {"administrator"}, "administrator_password_reset": {"administrator.password", "administrator.auth_generation"},
	"posting_resources_enable": {postingResourcesCollection},
	"posting_policies_enable":  {"rate_policy", "anon_policy"}, "admission_enable": {"rate_policy"}, "anonymous_enable": {"anon_policy"}, "anonymous_revoke": {"token_revocation"}, "anonymous_revoke_all": {"anon_policy.generation"},
	"board_provisioning": {"board_directory"}, "board_activated": {"board_directory.status"},
	"board_settings_enable": {"site.minimum_reader_version"}, "denial_rules_enable": {"site.minimum_reader_version"},
	"other_admin_operation": {},
}

// auditSummary は許可リストで操作名と項目名を選ぶ。自由記述の理由や保存値をコピーしない。
func auditSummary(owner domain.ID, kind string, rec store.Record, op store.ControlOperation) (AuditEntry, bool) {
	action := op.Actor.Reason
	fields, known := auditActions[action]
	if op.Actor.Kind != "admin" && !(op.Actor.Kind == "system" && known) {
		return AuditEntry{}, false
	}
	if !known {
		action = "other_admin_operation"
		fields = []string{}
	}
	entry := AuditEntry{ID: rec.ID, Owner: owner, OwnerKind: kind, Sequence: op.Seq, Committed: time.Unix(0, int64(op.Committed)).UTC().Format(time.RFC3339Nano), ActorKind: op.Actor.Kind, Action: action, Targets: append([]string{}, op.Result.Targets...), Fields: append([]string{}, fields...)}
	if strings.HasPrefix(op.Actor.Reason, "cap_command_") {
		entry.ActorKind = "cap"
		for _, m := range op.Mutations {
			if m.Collection == "cap_command" {
				var receipt capCommandReceipt
				if strictjson.Decode(m.Value, &receipt) == nil {
					phase := "開始"
					if receipt.Done {
						phase = "完了"
					}
					entry.Command = &CapCommandAudit{receipt.Thread, receipt.Post, capCommandDuration(capCommand{Kind: receipt.Kind, Minutes: receipt.Minutes}), phase}
				}
			}
		}
	}
	if kind == "board" {
		id := owner
		entry.Board = &id
	}
	if op.Actor.ID != nil {
		id := *op.Actor.ID
		entry.ActorID = &id
	}
	return entry, true
}

func auditCursor(s adminauth.Session, token string, index int) string {
	prefix := token + "." + strconv.Itoa(index)
	return prefix + "." + s.CSRF("audit-cursor:"+prefix)
}
func (r *Repository) auditPage(ctx context.Context, s adminauth.Session, q auditQuery, cursor string) (AuditPage, error) {
	return r.auditPageSnapshot(ctx, s, q, cursor, true)
}

// auditPageSnapshot は同じ権限・カーソルを検証し、資産の検証では一覧の収集・複製を省く。
func (r *Repository) auditPageSnapshot(ctx context.Context, s adminauth.Session, q auditQuery, cursor string, retainSnapshot bool) (AuditPage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, e := r.currentAdminSession(s); e != nil {
		return AuditPage{}, e
	}
	now := time.Now()
	for key, snap := range r.auditSnapshots {
		if !now.Before(snap.expires) {
			delete(r.auditSnapshots, key)
		}
	}
	var snap auditSnapshot
	var token string
	index := 0
	if cursor == "" && (q.Limit < 1 || q.Limit > 200) {
		return AuditPage{}, &adminFailure{status: 400, code: "INVALID_AUDIT_QUERY"}
	}
	if cursor != "" {
		parts := strings.Split(cursor, ".")
		if len(parts) != 3 || !s.CheckCSRF("audit-cursor:"+parts[0]+"."+parts[1], parts[2]) {
			return AuditPage{}, &adminFailure{status: 409, code: "AUDIT_CURSOR_INVALID"}
		}
		n, e := strconv.Atoi(parts[1])
		if e != nil || n < 0 || strconv.Itoa(n) != parts[1] {
			return AuditPage{}, &adminFailure{status: 409, code: "AUDIT_CURSOR_INVALID"}
		}
		token = parts[0]
		var ok bool
		snap, ok = r.auditSnapshots[token]
		if !ok || n >= len(snap.rows) || n%snap.query.Limit != 0 {
			return AuditPage{}, &adminFailure{status: 409, code: "AUDIT_SNAPSHOT_EXPIRED"}
		}
		index = n
	} else {
		if e := r.authorizeAuditBoards(s, q); e != nil {
			return AuditPage{}, e
		}
		if q.Board != (domain.ID{}) && r.posting[q.Board] == nil {
			return AuditPage{}, &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
		}
		if !retainSnapshot {
			return AuditPage{}, nil
		}
		rows, e := r.collectAudit(ctx, q)
		if e != nil {
			if errors.Is(e, errAuditCatchUp) {
				return AuditPage{}, &adminFailure{status: 503, code: "AUDIT_CATCH_UP_PENDING"}
			}
			if errors.Is(e, errAuditIndexFull) {
				return AuditPage{}, &adminFailure{status: 503, code: "AUDIT_INDEX_FULL"}
			}
			if errors.Is(e, store.ErrHistoryBudget) {
				return AuditPage{}, &adminFailure{status: 503, code: "AUDIT_RANGE_TOO_LARGE"}
			}
			return AuditPage{}, e
		}
		snap = auditSnapshot{q, rows, now.Add(10 * time.Minute)}
		if len(rows) > q.Limit && retainSnapshot {
			if len(r.auditSnapshots) >= 8 {
				return AuditPage{}, &adminFailure{status: 503, code: "AUDIT_SNAPSHOTS_FULL"}
			}
			var secret [32]byte
			if _, e = rand.Read(secret[:]); e != nil {
				return AuditPage{}, e
			}
			token = base64.RawURLEncoding.EncodeToString(secret[:])
			if r.auditSnapshots == nil {
				r.auditSnapshots = map[string]auditSnapshot{}
			}
			r.auditSnapshots[token] = snap
		}
	}
	if e := r.authorizeAuditBoards(s, snap.query); e != nil {
		return AuditPage{}, e
	}
	if !retainSnapshot {
		return AuditPage{}, nil
	}
	end := min(index+snap.query.Limit, len(snap.rows))
	page := AuditPage{Entries: append([]AuditEntry{}, snap.rows[index:end]...), From: snap.query.From.UTC().Format(time.RFC3339Nano), To: snap.query.To.UTC().Format(time.RFC3339Nano), Total: uint32(len(snap.rows))}
	page.Boards = slices.Clone(snap.query.Boards)
	page.Action, page.Limit = snap.query.Action, snap.query.Limit
	if snap.query.Board != (domain.ID{}) {
		page.Board = snap.query.Board.String()
	}
	if snap.query.Actor != (domain.ID{}) {
		page.Actor = snap.query.Actor.String()
	}
	if end < len(snap.rows) && token != "" {
		page.Next = auditCursor(s, token, end)
	}
	return page, nil
}

// authorizeAuditBoards はページ送りでも選択した全板の現在の担当を検査する。
func (r *Repository) authorizeAuditBoards(s adminauth.Session, q auditQuery) error {
	if len(q.Boards) == 0 {
		return r.authorizeAdmin(s, "board_admin", q.Board)
	}
	for _, id := range q.Boards {
		if e := r.authorizeAdmin(s, "board_admin", id); e != nil {
			return e
		}
		if r.posting[id] == nil {
			return &adminFailure{status: 404, code: "BOARD_NOT_FOUND"}
		}
	}
	return nil
}
