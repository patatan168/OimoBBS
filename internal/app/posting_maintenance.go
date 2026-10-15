// 所有ワーカー上で圧縮と旧世代回収の自動判断を実行する。
package app

import (
	"context"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"time"
)

// PostingMaintenanceReport は保守判断と保存処理の結果。本文・接続記録を含まない。
type PostingMaintenanceReport struct {
	Deferred string                        `json:"deferred"`
	Decision store.PackMaintenanceDecision `json:"decision"`
	Pack     PostingPackReport             `json:"pack"`
	Reclaim  store.ThreadReclaimReport     `json:"reclaim"`
}

// ErrPackCapacity は保存を始めずに延期できる容量不足を表す。
var ErrPackCapacity = errors.New("insufficient free capacity for pack")

// ErrPackPressure は投稿遅延のため圧縮を延期する判定。
var ErrPackPressure = errors.New("compaction deferred for posting latency")

// MaintainPack は所有ワーカーで必要な圧縮・回収を実行する。previewでは保存を変更しない。
func (p *PostingLog) MaintainPack(ctx context.Context, clock func() time.Time, apply bool) (PostingMaintenanceReport, error) {
	return p.MaintainPackWithAdmission(ctx, clock, apply, nil)
}

// MaintainPackWithAdmission は容量を予約できない圧縮を延期し、旧世代回収は続ける。
func (p *PostingLog) MaintainPackWithAdmission(ctx context.Context, clock func() time.Time, apply bool, acquire func() (func(), error)) (PostingMaintenanceReport, error) {
	var report PostingMaintenanceReport
	if e := ctx.Err(); e != nil {
		return report, e
	}
	if clock == nil || p.stopped {
		return report, errors.New("thread unavailable for maintenance")
	}
	if p.reclaimed != nil {
		report.Decision.Reason = "expired"
		return report, nil
	}
	if p.thread == nil {
		return report, errors.New("thread unavailable for maintenance")
	}
	now := domain.Time(clock().UnixNano())
	report.Decision = p.thread.MaintenanceInfo().Decision(now)
	if p.PublicExpired(now) {
		report.Decision.Compact = false
		report.Decision.Reason = "expired"
		return report, nil
	}
	var e error
	compact := apply && report.Decision.Compact
	if compact && acquire != nil {
		release, err := acquire()
		if errors.Is(err, ErrPackCapacity) {
			report.Deferred = "capacity"
			compact = false
		} else if errors.Is(err, ErrPackPressure) {
			report.Deferred = "latency"
			compact = false
		} else if err != nil {
			return report, err
		} else {
			defer release()
		}
	}
	if compact {
		report.Pack, e = p.CompactWithClock(ctx, clock, report.Decision.Level, true)
		if e != nil {
			return report, e
		}
	}
	if p.thread.MaintenanceInfo().Generation > 1 {
		report.Reclaim, e = p.thread.ReclaimOldFiles(false)
		if e != nil {
			return report, e
		}
		if apply && report.Reclaim.Files > 0 {
			report.Reclaim, e = p.ReclaimPack(ctx, domain.Time(clock().UnixNano()), true)
		}
	}
	return report, e
}
