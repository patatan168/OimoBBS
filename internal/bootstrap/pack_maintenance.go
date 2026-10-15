// 有限件数の投稿保守を板ワーカーへ分配し、巡回位置と公開可能な状態を管理する。
package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/board"
	"oimobbs/internal/domain"
	"oimobbs/internal/strictjson"
	"sort"
	"strconv"
	"strings"
	"time"
)

// PackMaintenanceConfig は明示的に有効化する保守巡回の上限。
type PackMaintenanceConfig struct {
	Enabled         bool `json:"enabled"`
	MaxSeconds      int  `json:"max_seconds"`
	IntervalSeconds int  `json:"interval_seconds"`
	MaxThreads      int  `json:"max_threads"`
}

// PackMaintenanceEntry は各スレッドの判定結果。
type PackMaintenanceEntry struct {
	Board  domain.ID `json:"board"`
	Thread uint64    `json:"thread"`
	app.PostingMaintenanceReport
}

// PackMaintenanceReport は一巡の有限batch。Nextは次回に渡す排他的cursor。
type PackMaintenanceReport struct {
	Complete       bool                   `json:"complete"`
	StopReason     string                 `json:"stop_reason"`
	DurationMillis int64                  `json:"duration_ms"`
	BusyBoards     int                    `json:"busy_boards"`
	Entries        []PackMaintenanceEntry `json:"entries"`
	Next           string                 `json:"next"`
	Applied        bool                   `json:"applied"`
}

// PackMaintenanceStatus は管理画面向けの状態。内部エラーやpathを公開しない。
type PackMaintenanceStatus struct {
	CapacityKnown   bool   `json:"capacity_known"`
	AvailableBytes  uint64 `json:"available_bytes"`
	ReservedBytes   uint64 `json:"reserved_bytes"`
	Deferred        int    `json:"deferred"`
	LatencyDeferred int    `json:"latency_deferred"`
	BusyBoards      int    `json:"busy_boards"`
	StopReason      string `json:"stop_reason"`
	DurationMillis  int64  `json:"duration_ms"`
	Enabled         bool   `json:"enabled"`
	Running         bool   `json:"running"`
	Failed          bool   `json:"failed"`
	Completed       string `json:"completed"`
	Scanned         int    `json:"scanned"`
	Compacted       int    `json:"compacted"`
	Reclaimed       int    `json:"reclaimed_files"`
}

// MaintenanceStatus は実行処理から独立したlockで状態を取得する。
func (r *Repository) MaintenanceStatus() PackMaintenanceStatus {
	r.maintenanceStatusMu.Lock()
	defer r.maintenanceStatusMu.Unlock()
	s := r.maintenanceStatus
	s.Enabled = r.operations().Maintenance.Enabled
	return s
}

// MaintainPostingPacks はboard/key順で最大limit件を調べる。全体lockをI/O中保持しない。
// afterが末尾を越えた場合は空のNextを返し、呼出側が次巡を先頭から始める。
func (r *Repository) MaintainPostingPacks(ctx context.Context, limit int, after string, apply bool) (report PackMaintenanceReport, err error) {
	clock := r.maintenanceClock
	if clock == nil {
		clock = time.Now
	}
	started := clock()
	seconds := 30
	if c := r.operations().Maintenance; c.MaxSeconds != 0 {
		seconds = c.MaxSeconds
	}
	expired := func() bool { return clock().Sub(started) >= time.Duration(seconds)*time.Second }
	defer func() { report.DurationMillis = max(int64(0), clock().Sub(started).Milliseconds()) }()
	report.Entries = []PackMaintenanceEntry{}
	report.Applied = apply
	report.Next = after
	if after != "" {
		parts := strings.Split(after, "/")
		if len(parts) != 2 {
			return report, errors.New("invalid maintenance cursor")
		}
		var owner domain.ID
		if e := owner.UnmarshalJSON([]byte(strconv.Quote(parts[0]))); e != nil {
			return report, errors.New("invalid maintenance cursor")
		}
		key, e := strconv.ParseUint(parts[1], 10, 64)
		if e != nil || key == 0 || maintenanceCursor(owner, key) != after {
			return report, errors.New("invalid maintenance cursor")
		}
	}
	if limit < 1 || limit > 1000 {
		return report, errors.New("maintenance limit must be 1..1000")
	}
	if !r.maintenanceMu.TryLock() {
		return report, errors.New("maintenance already running")
	}
	defer r.maintenanceMu.Unlock()
	r.maintenanceStatusMu.Lock()
	r.maintenanceStatus.Running = true
	r.maintenanceStatusMu.Unlock()
	defer func() {
		r.maintenanceStatusMu.Lock()
		defer r.maintenanceStatusMu.Unlock()
		s := &r.maintenanceStatus
		s.Running = false
		s.Failed = err != nil && !errors.Is(err, board.ErrBusy)
		s.StopReason = report.StopReason
		s.BusyBoards = report.BusyBoards
		if errors.Is(err, board.ErrBusy) {
			s.StopReason = "queue_busy"
		}
		s.DurationMillis = max(int64(0), clock().Sub(started).Milliseconds())
		s.Deferred = 0
		s.LatencyDeferred = 0
		s.Completed = time.Now().UTC().Format(time.RFC3339)
		s.Scanned = len(report.Entries)
		s.Compacted = 0
		s.Reclaimed = 0
		for _, entry := range report.Entries {
			if entry.Deferred == "latency" {
				s.LatencyDeferred++
			}
			if entry.Deferred == "capacity" {
				s.Deferred++
			}
			if entry.Pack.Applied {
				s.Compacted++
			}
			if entry.Reclaim.Applied {
				s.Reclaimed += entry.Reclaim.Files
			}
		}
	}()
	r.mu.Lock()
	if err = r.available(); err != nil {
		r.mu.Unlock()
		return
	}
	var state siteState
	err = strictjson.Decode(r.site.State().Rows["site:state"].Value, &state)
	if err == nil && apply && state.MinimumReader < 68 {
		err = errors.New("run pack enable before maintenance")
	}
	boards := make([]*postingBoard, 0, len(r.posting))
	for _, b := range r.posting {
		boards = append(boards, b)
	}
	r.mu.Unlock()
	if err != nil {
		return
	}
	sort.Slice(boards, func(i, j int) bool { return boards[i].owner.String() < boards[j].owner.String() })
	for _, b := range boards {
		if expired() {
			report.StopReason = "time_budget"
			return
		}
		if err = ctx.Err(); err != nil {
			return
		}
		value, e := b.worker.SubmitIdle(ctx, func() (any, error) {
			keys := make([]uint64, 0, len(b.threads))
			for key := range b.threads {
				keys = append(keys, key)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			return keys, nil
		})
		if errors.Is(e, board.ErrBusy) {
			report.BusyBoards++
			report.StopReason = "queue_busy"
			continue
		}
		if e != nil {
			return report, e
		}
		for _, key := range value.([]uint64) {
			cursor := maintenanceCursor(b.owner, key)
			if cursor <= after {
				continue
			}
			if expired() {
				report.StopReason = "time_budget"
				return
			}
			if len(report.Entries) == limit {
				report.StopReason = "thread_limit"
				report.Next = maintenanceCursor(report.Entries[len(report.Entries)-1].Board, report.Entries[len(report.Entries)-1].Thread)
				return
			}
			value, e = b.worker.SubmitIdle(ctx, func() (any, error) {
				if b.stopped || b.threads[key] == nil {
					return nil, ErrPostingUnavailable
				}
				if expired() {
					return nil, errPackTimeBudget
				}
				result, e := b.threads[key].MaintainPackWithAdmission(ctx, b.clock, apply, r.reservePack)
				if b.threads[key].StorageStopped() {
					b.stopped = true
				}
				return result, e
			})
			if errors.Is(e, board.ErrBusy) {
				report.BusyBoards++
				report.StopReason = "queue_busy"
				break
			}
			if errors.Is(e, errPackTimeBudget) {
				report.StopReason = "time_budget"
				return
			}
			if e != nil {
				return report, e
			}
			report.Entries = append(report.Entries, PackMaintenanceEntry{Board: b.owner, Thread: key, PostingMaintenanceReport: value.(app.PostingMaintenanceReport)})
			report.Next = cursor
		}
	}
	report.Next = ""
	report.Complete = report.BusyBoards == 0
	return
}

// maintenanceCursor は数字順と辞書順を一致させる固定幅cursorを返す。
func maintenanceCursor(owner domain.ID, key uint64) string {
	return fmt.Sprintf("%s/%020d", owner.String(), key)
}

// RunPackMaintenance は有効時だけ起動直後と各intervalで巡回する。失敗時は終了する。
func (r *Repository) RunPackMaintenance(ctx context.Context) error {
	cursor := ""
	for {
		c := r.operations().Maintenance
		if c.Enabled {
			report, e := r.MaintainPostingPacks(ctx, c.MaxThreads, cursor, true)
			if e != nil && !errors.Is(e, board.ErrBusy) {
				if ctx.Err() != nil {
					return nil
				}
				return e
			}
			cursor = report.Next
		}
		var timer *time.Timer
		var ticks <-chan time.Time
		if c.Enabled {
			timer = time.NewTimer(time.Duration(c.IntervalSeconds) * time.Second)
			ticks = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-r.maintenanceWake:
		case <-ticks:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
func (r *Repository) runPackMaintenance(ctx context.Context, ticks <-chan time.Time, limit int) error {
	cursor := ""
	for {
		report, e := r.MaintainPostingPacks(ctx, limit, cursor, true)
		if e != nil && !errors.Is(e, board.ErrBusy) {
			if ctx.Err() != nil {
				return nil
			}
			return e
		}
		cursor = report.Next
		select {
		case <-ctx.Done():
			return nil
		case _, ok := <-ticks:
			if !ok {
				return nil
			}
		}
	}
}

// ValidatePackMaintenance はリスナー公開前に明示的なreader移行を確認する。
func (r *Repository) ValidatePackMaintenance() error {
	if !r.operations().Maintenance.Enabled {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.available(); e != nil {
		return e
	}
	var state siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &state); e != nil {
		return e
	}
	if state.MinimumReader < 68 {
		return errors.New("run pack enable before automatic maintenance")
	}
	return nil
}

var errPackTimeBudget = errors.New("pack maintenance time budget exhausted")
