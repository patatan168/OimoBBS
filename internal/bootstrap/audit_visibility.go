// 管理操作一覧から内部の再開位置だけの更新を除き、既存の保存要約・移管証明は維持する。
package bootstrap

// auditVisible は旧版が要約へ保存した自動整理の進捗を、一覧・件数・ページ送りから除外する。
// 管理者による操作や自動整理の設定変更は引き続き表示する。
func auditVisible(entry AuditEntry) bool {
	return entry.ActorKind != "system" || entry.Action != "required_original_gc_progress"
}
