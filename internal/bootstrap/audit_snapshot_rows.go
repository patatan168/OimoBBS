// ページ送りは索引の不変参照を共有し、要約は返すページの分だけ作る。
package bootstrap

// auditSnapshotRow は取得時点の記録と表示分類を固定する。索引から期限回収されても内容は変わらない。
type auditSnapshotRow struct {
	record *auditIndexedEntry
	action string
}

// summary は保存正本を変更せず、取得時点の分類を持つ応答用コピーを返す。
func (row auditSnapshotRow) summary() AuditEntry {
	entry := row.record.entry
	if row.action != entry.Action {
		entry.Action = row.action
		entry.Fields = append([]string{}, auditSourceActions[row.action]...)
	}
	return entry
}

// auditSnapshotsFit は共有記録を一度だけ数え、参照配列と期限回収後も残る記録を128MiB以内に抑える。
// 256byteの記録管理分と24byteの参照分も加算し、通常の再取得で同じ本文を重複計上しない。
func auditSnapshotsFit(existing map[string]auditSnapshot, incoming []auditSnapshotRow) bool {
	seen := make(map[*auditIndexedEntry]struct{}, len(incoming))
	used := 0
	add := func(rows []auditSnapshotRow) bool {
		used += len(rows) * 24
		for _, row := range rows {
			if _, ok := seen[row.record]; ok {
				continue
			}
			seen[row.record] = struct{}{}
			used += row.record.bytes + 256
			if used > 128<<20 {
				return false
			}
		}
		return used <= 128<<20
	}
	if !add(incoming) {
		return false
	}
	for _, snapshot := range existing {
		if !add(snapshot.rows) {
			return false
		}
	}
	return true
}
