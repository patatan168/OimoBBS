// 案件copy・提出物生成の予約を投稿・圧縮・backupと共通のディスク余力へ接続する。
package bootstrap

import (
	"oimobbs/internal/disclosure"
	"oimobbs/internal/platform"
	"sync"
)

// reserveEvidence は最大64MiBの作業枠を先に確保し、終了後一度だけ返却する。
func (r *Repository) reserveEvidence() (func(), error) {
	return r.reservePrivateLogBytes(uint64(disclosure.MaxArtifactBytes))
}

// reservePrivateLogBytes は非公開ログ作業を共通余力へ予約し、必須投稿の床を維持する。
func (r *Repository) reservePrivateLogBytes(requested uint64) (func(), error) {
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	r.observePostingCapacity()
	if !r.postingCapacity.status.WriteReady {
		return nil, ErrPostingCapacity
	}
	status := r.postingCapacity.status
	reserved := r.packReserved + r.postReserved + r.backupReserved
	if status.AvailableBytes < reserved || status.AvailableBytes-reserved < status.FloorBytes+postingReservationBytes+requested {
		return nil, ErrPostingCapacity
	}
	r.postReserved += requested
	var once sync.Once
	return func() {
		once.Do(func() { r.packResourcesMu.Lock(); r.postReserved -= requested; r.packResourcesMu.Unlock() })
	}, nil
}

// reservePrivateReclaimBytes は既存予約を保護し、投稿の停止閾値内でも満了回収用の実空間を予約する。
// 新規投稿/保全のために床を消費する入口には使わない。回収不能なら対象を保持して失敗を示す。
func (r *Repository) reservePrivateReclaimBytes(requested uint64) (func(), error) {
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	probe := r.packSpace
	if probe == nil {
		probe = platform.Space
	}
	space, e := probe(r.cfg.DataDir)
	if e != nil {
		return nil, e
	}
	reserved := r.packReserved + r.postReserved + r.backupReserved
	if space.Available < reserved || requested > space.Available-reserved {
		return nil, ErrPostingCapacity
	}
	r.postReserved += requested
	var once sync.Once
	return func() {
		once.Do(func() { r.packResourcesMu.Lock(); r.postReserved -= requested; r.packResourcesMu.Unlock() })
	}, nil
}

// reservePrivateLossBytes は最小監視枠を予約し、投稿可能な最後の8MiB枠を先取りしない。
// 投稿容量を既に下回る場合は未使用実空間だけを使い、既存の投稿/backup予約を保護する。
func (r *Repository) reservePrivateLossBytes(requested uint64) (func(), error) {
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	probe := r.packSpace
	if probe == nil {
		probe = platform.Space
	}
	space, e := probe(r.cfg.DataDir)
	if e != nil {
		return nil, e
	}
	reserved := r.packReserved + r.postReserved + r.backupReserved
	if space.Available < reserved || requested > space.Available-reserved {
		return nil, ErrPostingCapacity
	}
	remaining := space.Available - reserved
	threshold := max(uint64(1<<30), space.Total/10) + postingReservationBytes
	if remaining >= threshold && remaining-requested < threshold {
		return nil, ErrPostingCapacity
	}
	r.postReserved += requested
	var once sync.Once
	return func() {
		once.Do(func() { r.packResourcesMu.Lock(); r.postReserved -= requested; r.packResourcesMu.Unlock() })
	}, nil
}
