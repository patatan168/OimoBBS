// 原本の自動回収を先行readerと耐久設定へ束縛し、一回128原本まで周期実行する。
package bootstrap

import (
	"context"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"reflect"
	"time"
)

// EnableRequiredOriginalReclamation は受理原本の公開回収を有効にし、最低reader48を先行保存する。
// 原本の自動走査設定を耐久保存し、毎分の案件整理から一回128原本まで回収する。
// 再送は進捗を初期化しない。独立backup/全保存コピー回収を有効にした意味ではない。
func (r *Repository) EnableRequiredOriginalReclamation(ctx context.Context) error {
	if e := r.EnablePublicBodyReclamation(ctx); e != nil {
		return e
	}
	if _, e := r.enableStorageReader(ctx, 48, "required_original_gc_enable"); e != nil {
		return e
	}
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	site, job, e := r.requiredGCJob(time.Now())
	if e != nil {
		return e
	}
	if job != nil {
		if job.Enabled {
			return nil
		}
		job.Enabled, job.At = true, domain.Time(time.Now().UnixNano())
		return r.saveRequiredGCJob(*job, "required_original_gc_configure")
	}
	v := requiredGCState{Schema: requiredGCStateSchema, Site: site.ID, Enabled: true, Round: 1, At: domain.Time(time.Now().UnixNano())}
	return r.saveRequiredGCJob(v, "required_original_gc_configure")
}

// DisableRequiredOriginalReclamation は進捗と最低readerを保持して、受理原本の新しい周期回収を止める。
// 確定済み回収の世代整理・案件/元予約・未受理24時間/接続7日の期限処理は停止しない。
func (r *Repository) DisableRequiredOriginalReclamation(ctx context.Context) error {
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	_, job, e := r.requiredGCJob(time.Now())
	if e != nil || job == nil {
		return e
	}
	if !job.Enabled {
		return nil
	}
	job.Enabled, job.At = false, domain.Time(time.Now().UnixNano())
	return r.saveRequiredGCJob(*job, "required_original_gc_configure")
}

// SweepRequiredOriginals は未受理の期限を先に整理し、受理原本は耐久設定に従い回収する。
// 一回の回収は最大128原本で、受理原本の走査は最大二段階進める。
// 失敗した段階の進捗を保存せず、保存済み位置から次回/再起動で再開する。
func (r *Repository) SweepRequiredOriginals(ctx context.Context) (int, error) {
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sweepRequiredOriginalsLocked(ctx)
}

func (r *Repository) requiredGCJob(now time.Time) (siteState, *requiredGCState, error) {
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return site, nil, e
	}
	job, e := readRequiredGCState(r.site.State(), site, domain.Time(now.UnixNano()))
	return site, job, e
}

// saveRequiredGCJob は原本回収後の位置をSyncし、保存不確定ならRepositoryを停止する。
func (r *Repository) saveRequiredGCJob(v requiredGCState, reason string) error {
	if e := appendControl(r.site, reason, []store.Mutation{mutation("required_gc", "originals", v, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}

func (r *Repository) sweepRequiredOriginalsLocked(ctx context.Context) (int, error) {
	if e := r.available(); e != nil {
		return 0, e
	}
	if e := ctx.Err(); e != nil {
		return 0, e
	}
	if n, e := r.sweepRejectedOriginalsLocked(ctx); e != nil || n != 0 {
		return n, e
	}
	for range 2 {
		n, changed, e := r.stepRequiredGCJobLocked(ctx)
		if e != nil || n != 0 || !changed {
			return n, e
		}
	}
	return 0, nil
}

// stepRequiredGCJobLocked は共通排他内で一段階を実行し、成功した意味のある進捗だけ保存する。
func (r *Repository) stepRequiredGCJobLocked(ctx context.Context) (int, bool, error) {
	if e := ctx.Err(); e != nil {
		return 0, false, e
	}
	now := time.Now()
	site, job, e := r.requiredGCJob(now)
	if e != nil || job == nil {
		return 0, false, e
	}
	if !job.Enabled {
		return 0, false, nil
	}
	next, removed, e := r.runRequiredGCJobLocked(ctx, site, *job, now)
	if e != nil {
		return removed, false, e
	}
	before := *job
	before.At = next.At
	if reflect.DeepEqual(before, next) {
		return removed, false, nil
	}
	e = r.saveRequiredGCJob(next, "required_original_gc_progress")
	return removed, e == nil, e
}
