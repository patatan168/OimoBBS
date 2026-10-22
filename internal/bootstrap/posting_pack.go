// 停止中の投稿pack生成・照合・適用を板ワーカーと最低reader版へ接続する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// EnablePostingPacks は版68と監査を同期し、旧readerによる保存先の起動を禁止する。
func (r *Repository) EnablePostingPacks(ctx context.Context) (ControlEnableReport, error) {
	return r.enableStorageReader(ctx, 68, "thread_pack_enable")
}

// CompactThread は指定スレッドを検証し、apply時だけpackへ切り替える。
// 停止中CLIを入口とし、世代切替全体を所有ワーカーで直列に実行する。
func (r *Repository) CompactThread(ctx context.Context, owner domain.ID, key uint64, level int, apply bool) (app.PostingPackReport, error) {
	if level != 0 && level != 1 && level != 6 && level != 9 {
		return app.PostingPackReport{}, errors.New("invalid compression level")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return app.PostingPackReport{}, e
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return app.PostingPackReport{}, e
	}
	if apply && site.MinimumReader < 68 {
		return app.PostingPackReport{}, errors.New("run pack enable before applying compaction")
	}
	b := r.posting[owner]
	if b == nil {
		return app.PostingPackReport{}, errors.New("posting board not found")
	}
	result, e := b.worker.Submit(ctx, func() (any, error) {
		if b.stopped || b.threads[key] == nil {
			return nil, ErrPostingUnavailable
		}
		if apply {
			release, e := r.reservePack()
			if e != nil {
				return nil, e
			}
			defer release()
		}
		report, e := b.threads[key].CompactWithClock(ctx, b.clock, uint8(level), apply)
		if b.threads[key].StorageStopped() {
			b.stopped = true
		}
		return report, e
	})
	if e != nil {
		return app.PostingPackReport{}, e
	}
	return result.(app.PostingPackReport), nil
}

// ReclaimThreadPack は署名照合後の旧投稿世代を停止中に回収する。
func (r *Repository) ReclaimThreadPack(ctx context.Context, owner domain.ID, key uint64, apply bool) (store.ThreadReclaimReport, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return store.ThreadReclaimReport{}, e
	}
	b := r.posting[owner]
	if b == nil {
		return store.ThreadReclaimReport{}, errors.New("posting board not found")
	}
	value, e := b.worker.Submit(ctx, func() (any, error) {
		if b.stopped || b.threads[key] == nil {
			return nil, ErrPostingUnavailable
		}
		report, e := b.threads[key].ReclaimPack(ctx, domain.Time(b.clock().UnixNano()), apply)
		if b.threads[key].StorageStopped() {
			b.stopped = true
		}
		return report, e
	})
	if e != nil {
		return store.ThreadReclaimReport{}, e
	}
	return value.(store.ThreadReclaimReport), nil
}
