// 旧上限まで保存済みの案件へ、先行reader49と有界な終端書込みを接続する。
package bootstrap

import (
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

// prepareCaseCompletionTailLocked は全案件の時計を確認し、旧上限案件があるときだけreader49を保存する。
// lifecycle/案件排他内で呼ぶ。reader保存失敗では物理copy回収/終端署名を開始しない。
func (r *Repository) prepareCaseCompletionTailLocked(now time.Time) error {
	if e := r.available(); e != nil {
		return e
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	needed, e := r.evidenceCases.NeedsCaseCompletionTail(domain.Time(now.UnixNano()))
	if e != nil {
		return e
	}
	if !needed && site.MinimumReader < 49 {
		return nil
	}
	if site.MinimumReader < 49 {
		site.MinimumReader = 49
		if e = appendControl(r.site, "case_completion_tail_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	return r.evidenceCases.EnableCaseCompletionTail(site.MinimumReader)
}

// ensureCaseCompletionForRequestLocked は現在認可/案件CAS確認後、解除の前提だけを準備する。
func (r *Repository) ensureCaseCompletionForRequestLocked(c disclosure.Case, actor domain.ID, etag, key, purpose string, now time.Time) error {
	if uint64(c.Revision) < disclosure.MaxCaseAudits {
		return nil
	}
	input := struct {
		Purpose string `json:"purpose"`
	}{purpose}
	_, replay, e := r.evidenceCases.Replay(c.ID, actor, "release", etag, key, input)
	if e != nil {
		return e
	}
	if !replay && c.ETag() != etag {
		return disclosure.ErrRevision
	}
	return r.prepareCaseCompletionTailLocked(now)
}
