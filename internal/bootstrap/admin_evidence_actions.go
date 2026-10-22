// 提出画面には通常の取得・期限管理と、処理途中だけの復旧を表示する。
package bootstrap

import (
	"oimobbs/internal/adminauth"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"time"
)

// evidenceStorageSummary は保存済み案件の状態を短く示し、完全性を推定しない。
func evidenceStorageSummary(c disclosure.Case, now time.Time) string {
	if c.State == "closed" {
		return "保全を終了し、コピーと提出ZIPを回収しました。"
	}
	if now.UnixNano() >= int64(c.Until) {
		return "保全期限が切れています。"
	}
	if c.State == "releasing" {
		return "保全コピーを回収中です。"
	}
	if c.State == "preparing" || c.HTTP != nil && c.HTTP.State == "preparing" {
		return "保全処理が途中です。再開すると同じ対象の処理を続けます。"
	}
	if c.State == "partial" || c.HTTP != nil && c.HTTP.State == "partial" {
		return "一部の記録が欠けています。保存済みの情報だけを出力します。"
	}
	if c.State == "draft" {
		return "対象は未確定です。ZIP取得時に期限内の記録を固定して保全します。"
	}
	if c.Rejected != nil {
		return "未受理の接続情報と結果を保全済みです。投稿本文は含みません。"
	}
	if c.HTTP != nil && c.HTTP.Unbound {
		return "受付前拒否・閲覧のHTTP記録を保全済みです。部分的な観測で、投稿本文は含みません。"
	}
	if c.HTTP != nil {
		return "投稿原本と関連HTTP記録を保全済みです。HTTPは部分的な観測です。"
	}
	return "投稿原本を保全済みです。関連HTTP記録はZIP作成時に確認します。"
}

// configureEvidenceActions は実行できる操作と途中の提出物だけを組み立てる。
func configureEvidenceActions(row *evidenceRow, s adminauth.Session, kind string, now time.Time) {
	c := row.Case
	if c.State == "closed" || now.UnixNano() >= int64(c.Until) {
		return
	}
	action := func(path, label string) evidenceAction {
		return evidenceAction{path, label, s.CSRF("/api/v1" + path), domain.NewID().String()}
	}
	base := "/evidence/cases/" + c.ID.String() + "/"
	if kind == "other" && (c.State == "draft" || c.State == "active" || c.State == "partial" || c.State == "preparing") {
		if c.HTTP == nil && (c.Rejected != nil || c.State == "draft") {
			a := action(base+"extract-rejected", "未受理ログのZIPを取得")
			row.RejectedExtract = &a
		}
		if c.Scope.Thread == 0 && c.Rejected == nil && (c.HTTP != nil && c.HTTP.Unbound || c.State == "draft") {
			a := action(base+"extract-http", "受付前拒否・閲覧のZIPを取得")
			row.HTTPExtract = &a
		}
	}
	if c.HTTP != nil && c.HTTP.State == "preparing" {
		row.Extract = nil
	}
	for _, a := range []*evidenceAction{row.Extract, row.RejectedExtract, row.HTTPExtract} {
		if a != nil {
			row.Downloads = append(row.Downloads, *a)
		}
	}
	if kind == "posts" && c.State == "preparing" && c.Rejected == nil && c.HTTP == nil {
		row.Actions = append(row.Actions, action(base+"hold", "保全処理を再開"))
	}
	if kind == "posts" && c.HTTP != nil && c.HTTP.State == "preparing" {
		row.Actions = append(row.Actions, action(base+"http-hold", "保全処理を再開"))
	}
	if c.State == "active" || c.State == "partial" {
		row.Actions = append(row.Actions, action(base+"extend", "保全期限を延長"))
	}
	row.Actions = append(row.Actions, action(base+"release", "保全を終了"))
	for _, v := range c.Exports {
		label := map[string]string{"preparing": "作成途中", "ready": "未取得", "consumed": "取得済み", "removed": "回収済み"}[v.State]
		item := evidenceExportRow{Export: v, Created: time.Unix(0, int64(v.Created)).In(domain.JST).Format("2006-01-02 15:04:05"), StateLabel: label}
		if (v.State == "preparing" || v.State == "ready") && now.UnixNano() < int64(v.Until) {
			item.Recoverable = true
			path := "/evidence/exports/" + v.ID.String()
			item.Download = action(path+"/download", "作成済みZIPを取得")
			item.Resume = action(path+"/resume", "ZIP作成を再開")
		}
		if !item.Recoverable && (v.State == "preparing" || v.State == "ready") {
			item.StateLabel = "期限切れ"
		}
		row.Exports = append(row.Exports, item)
	}
}
