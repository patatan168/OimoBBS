// 自動停止と成立した通報の参照を保持し、本文を一般制御ログへ複製しない。
package bootstrap

import (
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type autoReportEvidenceRef struct {
	Operation domain.ID           `json:"operation_id"`
	Target    autoReportReference `json:"target"`
}

// enableReportReviewReader はサイトmutex所有中に新規形式の版を先行同期する。
func (r *Repository) enableReportReviewReader() error {
	var site siteState
	if err := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); err != nil {
		return err
	}
	if site.MinimumReader >= 69 {
		return nil
	}
	site.MinimumReader = 69
	if err := appendControl(r.site, "auto_report_review_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); err != nil {
		r.stopped = true
		return err
	}
	return nil
}

func validateAutoReportRefs(r denialRule) error {
	if len(r.Reports) == 0 {
		if r.ReportPolicy != nil {
			return store.ErrCorrupt
		}
		return nil
	}
	p := ruleReportPolicy(r)
	if r.ReportPolicy == nil || !p.valid() || len(r.Reports) != p.Quorum || r.Reason != "abuse" || r.Effect.Type != "deny" || len(r.Conditions) != 1 || r.Conditions[0].Field != "token" || r.Conditions[0].Operator != "exact" || r.Expires-r.Starts != domain.Time(p.stop()) {
		return store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, ref := range r.Reports {
		if ref.Operation == (domain.ID{}) || seen[ref.Operation] || !validBoardKey(ref.Target.Board) || ref.Target.Key == 0 || ref.Target.Post == 0 {
			return store.ErrCorrupt
		}
		seen[ref.Operation] = true
	}
	if !seen[r.ID] {
		return errors.New("automatic stop must reference its deciding report")
	}
	return nil
}

// automaticStopRule は保存済み成立票がある自動停止だけを選ぶ。
func automaticStopRule(r denialRule) bool {
	return len(r.Reports) > 0
}
