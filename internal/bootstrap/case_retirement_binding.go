// 起動後の作成再送を現在siteに登録した回収HMACへ束縛し、削除した案件IDの再出現を拒否する。
package bootstrap

import (
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
	"time"
)

// bindCaseRetirementsLocked は現在site登録を案件所有者へ渡す。未返却の起動所有者か共通排他で呼ぶ。
func (r *Repository) bindCaseRetirementsLocked(now time.Time) error {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	rows, e := caseRetirementRegistrations(r.site.State(), site)
	if e != nil {
		return e
	}
	events := make(map[domain.Hash]evidence.Event, len(rows))
	for fingerprint, row := range rows {
		events[fingerprint] = row.Event
	}
	return r.evidenceCases.BindCaseRetirements(events, site.MinimumReader, now)
}
