// 期限失効を本文のない台帳へ保存し、板所有列と一つのタイマーで取りこぼしを走査する。
package bootstrap

import (
	"container/heap"
	"context"
	"errors"
	"strings"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type expiryDeadline struct {
	key uint64
	at  domain.Time
}
type expiryHeap []expiryDeadline

// EnableThreadRetention は期限writerの開始前にreader16をSyncし、起動時の失効を保存する。
// 停止中の検査/previewだけでは保存形式を変更しない。HTTP起動はlisten前に呼ぶ。
func (r *Repository) EnableThreadRetention(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	if r.captureValidator == nil {
		return ErrPostingUnavailable
	}
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		return e
	}
	if site.MinimumReader < 16 {
		site.MinimumReader = 16
		if e := appendControl(r.site, "thread_expiry_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{}); e != nil {
			r.stopped = true
			return e
		}
	}
	for _, b := range r.posting {
		if _, e := b.worker.Submit(ctx, func() (any, error) { return nil, b.enableRetention(site.PublicRevision) }); e != nil {
			return e
		}
	}
	return nil
}

func (b *postingBoard) enableRetention(siteVersion domain.U64) error {
	if b.expiryCancel != nil {
		return nil
	}
	b.expirySiteVersion = siteVersion
	b.retentionEnabled = true
	for key, p := range b.threads {
		b.bindExpiry(key, p)
	}
	delay, e := b.scanExpiry(true)
	if e != nil {
		return e
	}
	b.startExpiry(delay)
	return nil
}

func (h expiryHeap) Len() int           { return len(h) }
func (h expiryHeap) Less(i, j int) bool { return h[i].at < h[j].at }
func (h expiryHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(v any)        { *h = append(*h, v.(expiryDeadline)) }
func (h *expiryHeap) Pop() any {
	v := (*h)[len(*h)-1]
	*h = (*h)[:len(*h)-1]
	return v
}

// bindExpiry は新規/復旧スレッドへ耐久保存callbackと期限順の予約を登録する。
// heapと時計は板所有列内でだけ参照し、送信列から台帳writerを呼ばない。
func (b *postingBoard) bindExpiry(key uint64, p *app.PostingLog) {
	if p.Reclaimed() {
		return
	}
	p.SetExpiryPersistence(func(seq domain.U64, expires domain.Time, policy domain.U64, observed domain.Time) error {
		return b.saveExpiry(key, seq, expires, policy, observed)
	})
	if _, at, _, ok := p.RetentionState(); ok {
		heap.Push(&b.expiryHeap, expiryDeadline{key, at})
	}
	if b.expiryWake != nil {
		select {
		case b.expiryWake <- struct{}{}:
		default:
		}
	}
}

// saveExpiry は固定IDのexpireを先行Syncし、期限後の本文操作を追加しない。
func (b *postingBoard) saveExpiry(key uint64, seq domain.U64, expires domain.Time, policy domain.U64, now domain.Time) error {
	if b.stopped {
		return ErrPostingUnavailable
	}
	if log := b.deletions[key]; log != nil {
		for name, row := range log.State().Rows {
			if !strings.HasPrefix(name, "deletion:") {
				continue
			}
			var v DeletionRecord
			if e := strictjson.Decode(row.Value, &v); e != nil {
				b.stopped = true
				return e
			}
			if v.Kind == "expire" {
				if v.Expires != expires || v.Expected != seq {
					b.stopped = true
					return app.ErrEvidenceGap
				}
				_, e := b.resumeExpiry(v, b.threads[key])
				return e
			}
		}
	}
	var state boardValue
	if e := strictjson.Decode(b.control.State().Rows["board:state"].Value, &state); e != nil {
		b.stopped = true
		return e
	}
	siteVersion := b.expirySiteVersion
	if b.currentSiteRevision != nil {
		siteVersion = b.currentSiteRevision()
	}
	v := DeletionRecord{ID: domain.NewID(), Board: b.owner, Thread: domain.U64(key), Kind: "expire", Ranges: []app.RedactionRange{}, Expected: seq, TargetOperation: domain.NewID(), Format: 1, Phase: "intent", Created: now, Expires: expires, CleanupDue: expires + 300e9, Actor: domain.Actor{Kind: "system", Reason: "thread_expire"}, Versions: domain.Versions{Site: siteVersion, Board: state.Settings.Version, Thread: policy}, Audit: "pending"}
	if e := b.saveDeletion(v); e != nil {
		b.stopped = true
		return e
	}
	if e := b.afterDeletion("expiry:intent"); e != nil {
		b.stopped = true
		return e
	}
	_, e := b.resumeExpiry(v, b.threads[key])
	return e
}

// resumeExpiry は元期限と確定位置を照合して失効を復元する。本文WALは増やさない。
func (b *postingBoard) resumeExpiry(v DeletionRecord, p *app.PostingLog) (DeletionRecord, error) {
	defer b.pruneGuard()
	fail := func(e error) (DeletionRecord, error) { b.stopped = true; return v, e }
	if p == nil {
		return fail(app.ErrEvidenceGap)
	}
	seq, expires, _, ok := p.RetentionState()
	if !ok || seq != v.Expected || expires != v.Expires {
		return fail(app.ErrEvidenceGap)
	}
	p.RestoreExpired()
	for v.Phase != "applied" && v.Phase != "cleaning" {
		switch v.Phase {
		case "intent":
			v.Phase = "public_stopped"
		case "public_stopped":
			v.Phase = "applied"
		default:
			return fail(app.ErrEvidenceGap)
		}
		if e := b.saveDeletion(v); e != nil {
			return fail(e)
		}
		if e := b.afterDeletion("expiry:" + v.Phase); e != nil {
			return fail(e)
		}
	}
	return v, nil
}

// scanExpiry はdue順の処理に加え、送信側の失効を毎分所有者へ引き渡す。
func (b *postingBoard) scanExpiry(full bool) (time.Duration, error) {
	if b.stopped {
		return time.Minute, ErrPostingUnavailable
	}
	now := domain.Time(b.clock().UnixNano())
	for len(b.expiryHeap) != 0 && b.expiryHeap[0].at <= now {
		v := heap.Pop(&b.expiryHeap).(expiryDeadline)
		if p := b.threads[v.key]; p != nil {
			p.PublicExpired(now)
		}
		if b.stopped {
			return time.Minute, ErrPostingUnavailable
		}
	}
	if full {
		for _, p := range b.threads {
			p.PublicExpired(now)
			if b.stopped {
				return time.Minute, ErrPostingUnavailable
			}
		}
	}
	delay := time.Minute
	if len(b.expiryHeap) != 0 {
		delay = min(delay, time.Duration(b.expiryHeap[0].at-now))
	}
	return max(time.Millisecond, delay), nil
}

// startExpiry は板あたり一つの待機タイマーを開始する。起動時走査は公開前に済ませる。
func (b *postingBoard) startExpiry(delay time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	b.expiryCancel, b.expiryDone = cancel, make(chan struct{})
	b.expiryWake = make(chan struct{}, 1)
	go func() {
		defer close(b.expiryDone)
		lastFull := time.Now()
		timer := time.NewTimer(delay)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			case <-b.expiryWake:
			}
			full := time.Since(lastFull) >= time.Minute
			value, e := b.worker.Submit(ctx, func() (any, error) {
				delay, e := b.scanExpiry(full)
				if e == nil && full {
					e = b.cleanRedactions(8)
				}
				if e == nil && full {
					e = b.cleanPublicBodies(8)
				}
				return delay, e
			})
			if full {
				lastFull = time.Now()
			}
			if e != nil {
				if errors.Is(e, context.Canceled) || ctx.Err() != nil {
					return
				}
				timer.Reset(time.Minute)
				continue
			}
			timer.Reset(max(time.Millisecond, min(value.(time.Duration), time.Minute-time.Since(lastFull))))
		}
	}()
}
