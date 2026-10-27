// 起動/周期で先行署名済み延長intentのmetadata確定だけを再開する。
package bootstrap

import (
	"context"
	"time"
)

// reconcilePendingOptionalExtensionsLocked は案件mutex下で入り、lifecycle待ちと元待ち中は解放する。
// 新たな保全範囲や期限を承認せず、既存署名intentをその要求者の履歴として完了する。
func (r *Repository) reconcilePendingOptionalExtensionsLocked(ctx context.Context) error {
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if r.optionalStore == nil {
		return nil
	}
	if e := r.evidenceCases.Sweep(time.Now()); e != nil {
		return e
	}
	cases, e := r.evidenceCases.Cases()
	if e != nil {
		return e
	}
	for _, c := range cases {
		if c.Extension == nil || c.Extension.State != "pending" || terminalOptionalCase(c) {
			continue
		}
		if e = ctx.Err(); e != nil {
			return e
		}
		if _, e = r.renewPendingExtension(ctx, c, r.optionalStore, nil); e != nil {
			return e
		}
	}
	return nil
}

// reconcileOptionalRetention は新期限の段階確定を先行し、終端参照採用/解除まで同じ巡回で進める。
func (r *Repository) reconcileOptionalRetention(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.reconcilePendingOptionalExtensionsLocked(ctx); e != nil {
		return e
	}
	return r.reconcileTerminalOptionalHoldsLocked(ctx)
}
