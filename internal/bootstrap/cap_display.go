// キャップ表示を変える前に旧readerの書き込みを防ぐ境界を同期保存する。
package bootstrap

import (
	"context"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// ensureCapDisplayReader は認証済み資格の投稿前にreader36、CAP専用作成前にreader71を保存する。
// 板workerを待つ前にサイト所有mutexで完了し、保存が不明なら投稿を停止する。
func (r *Repository) ensureCapDisplayReader(ctx context.Context, b *postingBoard, id domain.ID, secret string, create bool, capOnly bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	required := uint32(36)
	if capOnly {
		required = 71
	}
	if site.MinimumReader >= required {
		return nil
	}
	if _, e := authenticateCap(r.liveCaps.Load(), b.capKey, id, secret, b.owner, create, domain.Time(b.clock().UnixNano())); e != nil {
		return e
	}
	site.MinimumReader = required
	if e := appendControl(r.site, "cap_display_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
		r.stopped = true
		return e
	}
	return nil
}
