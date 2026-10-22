// 監査HTMLの日時・板名と、閲覧範囲内の記録に基づく操作者の選択肢を整える。
package bootstrap

import (
	"oimobbs/internal/adminauth"
	"sort"
	"strconv"
	"strings"
	"time"
)

// auditTimeLabel は検索APIのUTC日時を、管理画面用の日本時間に変換する。
func auditTimeLabel(raw string) string {
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return raw
	}
	return at.In(time.FixedZone("JST", 9*60*60)).Format("2006/01/02 15:04:05")
}

// newAuditRow は固定された記録に表示ラベルを付ける。削除済み板はIDで識別できる。
func newAuditRow(entry AuditEntry, boards []boardOption) auditRow {
	row := auditRow{Entry: entry, Label: auditLabels[entry.Action], TimeLabel: auditTimeLabel(entry.Committed), BoardLabel: "サイト全体"}
	if row.Label == "" {
		row.Label = "詳細未記録の管理操作"
	}
	row.Description = describeAuditOperation(entry, row.Label)
	row.FieldLabels = describeAuditFields(entry.Fields)
	row.ActorLabel = "ローカル操作／システム"
	if entry.ActorID != nil {
		row.ActorLabel = "管理者"
		row.ActorShortID = entry.ActorID.String()[:8] + "…"
		if entry.ActorKind == "cap" {
			row.ActorLabel = "CAP"
		}
	}
	if entry.Board != nil {
		row.BoardLabel = "板ID：" + entry.Board.String()
		for _, b := range boards {
			if b.ID == *entry.Board {
				row.BoardLabel = b.Name + "（" + b.Key + "）"
				break
			}
		}
	}
	if entry.Command != nil {
		if strings.HasPrefix(entry.Action, "cap_command_ban") {
			if entry.Command.Duration == "permanent" {
				row.DurationLabel = "期限なし"
			} else if strings.HasSuffix(entry.Command.Duration, "m") {
				if minutes, err := strconv.ParseUint(strings.TrimSuffix(entry.Command.Duration, "m"), 10, 32); err == nil {
					row.DurationLabel = strconv.FormatUint(minutes, 10) + "分"
				}
			}
		}
		switch entry.Command.Phase {
		case "開始":
			row.PhaseLabel = "開始（完了未確認）"
		case "完了":
			row.PhaseLabel = "完了"
		default:
			row.PhaseLabel = entry.Command.Phase
		}
	}
	return row
}

// auditActorOptions は同期済み索引から期間・板に該当するIDを集める。
// 操作種別・操作者・ページ位置には依存させず、担当外の記録は選択肢にも含めない。
func (r *Repository) auditActorOptions(s adminauth.Session, page AuditPage) ([]auditOption, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	q := auditQuery{Boards: page.Boards}
	if page.Board != "" {
		_ = q.Board.UnmarshalJSON([]byte(`"` + page.Board + `"`))
	}
	if err := r.authorizeAuditBoards(s, q); err != nil {
		return nil, err
	}
	from, _ := time.Parse(time.RFC3339Nano, page.From)
	to, _ := time.Parse(time.RFC3339Nano, page.To)
	names := map[string]string{}
	account, err := r.currentAdminSession(s)
	if err != nil {
		return nil, err
	}
	names[account.ID.String()] = account.Display + "（" + account.Login + "）"
	if account.Role == "site_admin" && s.Reauthenticated(time.Now()) {
		admins, err := r.administrators()
		if err != nil {
			return nil, err
		}
		for _, admin := range admins {
			names[admin.ID.String()] = admin.Display + "（" + admin.Login + "）"
		}
	}
	actors := map[string]string{}
	if r.auditIndex != nil {
		for _, rows := range r.auditIndex.days {
			for _, row := range rows {
				entry := row.entry
				if entry.ActorID == nil || row.at.Before(from) || !row.at.Before(to) || !auditMatches(entry, q) {
					continue
				}
				kind := "管理者"
				if entry.ActorKind == "cap" {
					kind = "CAP"
				}
				id := entry.ActorID.String()
				actors[id] = kind + "：" + id
				if entry.ActorKind != "cap" && names[id] != "" {
					actors[id] = names[id]
				}
			}
		}
	}
	// 記録の期限切れや結果0件でも、指定済みIDを消して別条件へ変えない。
	if page.Actor != "" && actors[page.Actor] == "" {
		actors[page.Actor] = "指定中のID：" + page.Actor
	}
	options := make([]auditOption, 0, len(actors))
	for id, label := range actors {
		options = append(options, auditOption{id, label})
	}
	sort.Slice(options, func(i, j int) bool { return options[i].Label < options[j].Label })
	return options, nil
}
