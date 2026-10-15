// 投稿packの旧新共存に必要な容量を、Repository全体で予約する。
package bootstrap

import (
	"errors"
	"oimobbs/internal/app"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"sync"
)

const packReservationBytes uint64 = store.MaxPackFile + 16<<20

// packCapacity は固定の投稿停止水準を残し、未解放の保守予約も差し引く。
func packCapacity(space platform.DiskSpace, reserved uint64) bool {
	floor := max(uint64(1<<30), space.Total/10)
	if space.Available < floor || reserved > space.Available-floor {
		return false
	}
	return space.Available-floor-reserved >= packReservationBytes
}

// reservePack は空き容量を都度確認し、呼出元の全終了経路で解放できる予約を返す。
// filesystem自体の確保ではなく、同じRepository内の保守処理間の予約である。
func (r *Repository) reservePack() (func(), error) {
	return r.reservePackWithPressure(true)
}

// reserveDeletionPack は削除期限の回収を投稿遅延だけで延期しない。容量の上限は維持する。
func (r *Repository) reserveDeletionPack() (func(), error) {
	return r.reservePackWithPressure(false)
}

func (r *Repository) reservePackWithPressure(checkLatency bool) (func(), error) {
	if checkLatency && r.PostingLatency().Paused {
		return nil, app.ErrPackPressure
	}
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	probe := r.packSpace
	if probe == nil {
		probe = platform.Space
	}
	reserve, reserveErr := inspectEmergencyReserve(r.cfg.DataDir)
	if reserveErr != nil || reserve.Enabled && !reserve.Ready {
		return nil, app.ErrPackCapacity
	}
	space, e := probe(r.cfg.DataDir)
	if e != nil {
		r.maintenanceStatusMu.Lock()
		r.maintenanceStatus.CapacityKnown = false
		r.maintenanceStatusMu.Unlock()
		return nil, errors.New("cannot inspect pack storage capacity")
	}
	r.maintenanceStatusMu.Lock()
	r.maintenanceStatus.AvailableBytes = space.Available
	r.maintenanceStatus.ReservedBytes = r.packReserved
	r.maintenanceStatus.CapacityKnown = true
	r.maintenanceStatusMu.Unlock()
	if !packCapacity(space, r.packReserved+r.postReserved+r.backupReserved) {
		return nil, app.ErrPackCapacity
	}
	r.packReserved += packReservationBytes
	r.setPackReserved()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.packResourcesMu.Lock()
			defer r.packResourcesMu.Unlock()
			r.packReserved -= packReservationBytes
			r.setPackReserved()
		})
	}, nil
}
func (r *Repository) setPackReserved() {
	r.maintenanceStatusMu.Lock()
	defer r.maintenanceStatusMu.Unlock()
	r.maintenanceStatus.ReservedBytes = r.packReserved
}

// AvailableMiB は前回確認した利用可能容量を管理画面へ表示する。
func (s PackMaintenanceStatus) AvailableMiB() uint64 { return s.AvailableBytes >> 20 }

// ReservedMiB は現在の保守予約を管理画面へ表示する。
func (s PackMaintenanceStatus) ReservedMiB() uint64 { return s.ReservedBytes >> 20 }

// StopLabel は固定の巡回終了理由を日本語へ変換する。
func (s PackMaintenanceStatus) StopLabel() string {
	if s.Failed {
		return "エラーにより中断"
	}
	switch s.StopReason {
	case "time_budget":
		return "時間上限により次回へ継続"
	case "thread_limit":
		return "件数上限により次回へ継続"
	case "queue_busy":
		return "板が混雑しているため延期"
	default:
		return "一巡完了"
	}
}
