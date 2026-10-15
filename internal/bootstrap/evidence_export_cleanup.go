// 旧上限案件の提出物だけの期限回収へreader50を先行保存する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

// prepareCaseExportCleanupLocked は案件期限前に提出物が満了したときだけ新しい回収を有効にする。
// 案件排他内で呼び、reader保存不確定ならコピー/提出物を削除せず停止する。
func (r *Repository) prepareCaseExportCleanupLocked(now time.Time) error {
	if e := r.available(); e != nil {
		return e
	}
	needed, e := r.evidenceCases.NeedsExportCleanup(domain.Time(now.UnixNano()))
	if e != nil {
		return e
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if !needed && site.MinimumReader < 50 {
		return nil
	}
	if site.MinimumReader < 50 {
		site.MinimumReader = 50
		if e = appendControl(r.site, "case_export_cleanup_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	return r.evidenceCases.EnableExportCleanup(site.MinimumReader)
}
