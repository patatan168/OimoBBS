// 投稿の空き容量判定と、回復時に受付が頻繁に切り替わることを防ぐ状態を管理する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/platform"
	"sync"
	"time"
)

// ErrPostingCapacity は保存開始前に拒否した投稿容量不足・容量確認不能を表す。
var ErrPostingCapacity = errors.New("posting storage capacity unavailable")

const postingReservationBytes uint64 = 8 << 20

// PostingCapacityStatus は管理認証の内側にだけ公開する容量状態。
type PostingCapacityStatus struct {
	EmergencyReserve EmergencyReserveStatus `json:"emergency_reserve"`
	Known            bool                   `json:"known"`
	WriteReady       bool                   `json:"write_ready"`
	Recovering       bool                   `json:"recovering"`
	AvailableBytes   uint64                 `json:"available_bytes"`
	FloorBytes       uint64                 `json:"floor_bytes"`
	ReservedBytes    uint64                 `json:"reserved_bytes"`
	Checked          string                 `json:"checked"`
}
type postingCapacityState struct {
	status         PostingCapacityStatus
	blocked        bool
	recovery, last time.Time
}

// observe は十分な容量を30秒観測してから再開する。5秒超の観測欠落・時計逆行では待ち直す。
func (s *postingCapacityState) observe(space platform.DiskSpace, reserved uint64, now time.Time, probeErr error) {
	s.status = PostingCapacityStatus{Known: probeErr == nil, AvailableBytes: space.Available, FloorBytes: max(uint64(1<<30), space.Total/10), ReservedBytes: reserved, Checked: now.UTC().Format(time.RFC3339)}
	gap := now.Sub(s.last)
	if gap < 0 || gap > 5*time.Second {
		s.recovery = time.Time{}
	}
	s.last = now
	available := uint64(0)
	if space.Available >= reserved {
		available = space.Available - reserved
	}
	if probeErr != nil || available < s.status.FloorBytes+postingReservationBytes {
		s.blocked = true
		s.recovery = time.Time{}
		return
	}
	if !s.blocked {
		s.status.WriteReady = true
		return
	}
	if available < s.status.FloorBytes+(256<<20)+postingReservationBytes {
		s.recovery = time.Time{}
		return
	}
	if s.recovery.IsZero() {
		s.recovery = now
	}
	if now.Sub(s.recovery) >= 30*time.Second {
		s.blocked = false
		s.recovery = time.Time{}
		s.status.WriteReady = true
		return
	}
	s.status.Recovering = true
}

// observePostingCapacity は容量台帳lockの内側でだけ呼ぶ。
func (r *Repository) observePostingCapacity() {
	probe := r.packSpace
	if probe == nil {
		probe = platform.Space
	}
	clock := r.capacityClock
	if clock == nil {
		clock = time.Now
	}
	space, e := probe(r.cfg.DataDir)
	reserve, reserveErr := inspectEmergencyReserve(r.cfg.DataDir)
	if reserveErr != nil || reserve.Enabled && !reserve.Ready {
		e = errors.Join(e, errors.New("emergency reserve requires recovery"))
	}
	r.postingCapacity.observe(space, r.packReserved+r.postReserved+r.backupReserved, clock(), e)
	r.postingCapacity.status.EmergencyReserve = reserve
}

// reservePosting は新規受理前に全板共通の容量を予約し、完了時の解放関数を返す。
func (r *Repository) reservePosting() (func(), error) {
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	r.observePostingCapacity()
	if !r.postingCapacity.status.WriteReady {
		return nil, ErrPostingCapacity
	}
	r.postReserved += postingReservationBytes
	var once sync.Once
	return func() {
		once.Do(func() {
			r.packResourcesMu.Lock()
			defer r.packResourcesMu.Unlock()
			r.postReserved -= postingReservationBytes
		})
	}, nil
}

// PostingCapacity は容量を再確認して管理状態を返す。本文・保存pathを含めない。
func (r *Repository) PostingCapacity() PostingCapacityStatus {
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	r.observePostingCapacity()
	return r.postingCapacity.status
}

// RunStorageMonitor は投稿がない間も回復条件を観測し、容量取得失敗でも閲覧を停止しない。
func (r *Repository) RunStorageMonitor(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		r.PostingCapacity()
		r.PostingLatency()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// AvailableMiB は管理画面用の空き容量表示。
func (s PostingCapacityStatus) AvailableMiB() uint64 { return s.AvailableBytes >> 20 }
