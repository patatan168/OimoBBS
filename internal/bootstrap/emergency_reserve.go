// 停止中の排他の下で、掃除記録用の実ディスク領域を確保・解放する。
package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"oimobbs/internal/platform"
	"oimobbs/internal/store"
)

const emergencyReserveName = "emergency.reserve"
const emergencyReserveBytes int64 = 256 << 20

// EmergencyReserveStatus は予約ファイルの実割当を表す。未導入は従来動作を維持する。
type EmergencyReserveStatus struct {
	Enabled        bool  `json:"enabled"`
	Ready          bool  `json:"ready"`
	Bytes          int64 `json:"bytes"`
	AllocatedBytes int64 `json:"allocated_bytes"`
}

// inspectEmergencyReserve はリンク・権限・異常サイズを拒否し、疎なファイルを確保済みと扱わない。
func inspectEmergencyReserve(root string) (EmergencyReserveStatus, error) {
	path := filepath.Join(root, emergencyReserveName)
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return EmergencyReserveStatus{}, nil
	}
	s := EmergencyReserveStatus{Enabled: true}
	if e != nil {
		return s, e
	}
	if e = privatePath(path, false); e != nil {
		return s, e
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Size() < 0 || info.Size() > emergencyReserveBytes || stat.Blocks < 0 || stat.Blocks > (1<<63-1)/512 {
		return s, errors.New("invalid emergency reserve")
	}
	s.Bytes, s.AllocatedBytes = info.Size(), stat.Blocks*512
	s.Ready = s.Bytes == emergencyReserveBytes && s.AllocatedBytes >= emergencyReserveBytes
	return s, nil
}

// ManageEmergencyReserve は稼働writerと排他し、prepareで256MiBを実割当する。
// releaseはremaining以下にだけ縮小するため同じ指定の再実行で追加解放しない。
// applyなしは読取りだけ。I/O失敗後はファイルを残し、投稿を再開しない。
func ManageEmergencyReserve(cfg Config, action string, remaining int64, apply bool) (EmergencyReserveStatus, error) {
	return manageEmergencyReserve(cfg, action, remaining, apply, func(f *os.File) error { return syscall.Fallocate(int(f.Fd()), 0, 0, emergencyReserveBytes) })
}

// manageEmergencyReserve の割当関数は容量競合による失敗を再現する試験境界。
func manageEmergencyReserve(cfg Config, action string, remaining int64, apply bool, allocate func(*os.File) error) (status EmergencyReserveStatus, err error) {
	if action != "status" && action != "prepare" && action != "release" {
		return status, errors.New("invalid reserve action")
	}
	if action == "status" && apply {
		return status, errors.New("status does not accept apply")
	}
	if action == "release" && (remaining < 0 || remaining >= emergencyReserveBytes) {
		return status, errors.New("remaining bytes must be in 0..268435455")
	}
	if err = cfg.validate(); err != nil {
		return status, err
	}
	for _, path := range []string{cfg.DataDir, filepath.Join(cfg.DataDir, ".lock"), filepath.Join(cfg.DataDir, "instance.json")} {
		if err = privatePath(path, path == cfg.DataDir); err != nil {
			return status, err
		}
	}
	lock, err := platform.Lock(cfg.DataDir)
	if err != nil {
		return status, err
	}
	defer func() { err = errors.Join(err, platform.Unlock(lock)) }()
	status, err = inspectEmergencyReserve(cfg.DataDir)
	if err != nil || action == "status" || !apply {
		return status, err
	}
	if action == "release" && !status.Enabled {
		return status, errors.New("emergency reserve is not prepared")
	}
	if action == "prepare" {
		// 新規導入・補充は通常の構造検査を通す。解放は復旧途中のjournalを開かず実行できる。
		if _, err = checkLockedPosting(cfg, false, true); err != nil {
			return status, err
		}
		space, e := platform.Space(cfg.DataDir)
		if e != nil {
			return status, e
		}
		if !emergencyReserveCapacity(space, status, 0) {
			return status, errors.New("insufficient capacity to prepare emergency reserve")
		}
	}
	return writeEmergencyReserve(cfg.DataDir, action, remaining, status, allocate)
}

// emergencyReserveCapacity は追加の実割当と既存予約を差し引き、通常の停止水準を残す。
func emergencyReserveCapacity(space platform.DiskSpace, status EmergencyReserveStatus, held uint64) bool {
	need := uint64(emergencyReserveBytes - min(status.AllocatedBytes, emergencyReserveBytes))
	floor := max(uint64(1<<30), space.Total/10)
	return space.Available >= floor && held <= space.Available-floor && need <= space.Available-floor-held
}

// writeEmergencyReserve は呼出元の排他下で印・実割当・同期を行う。失敗した印も保持する。
func writeEmergencyReserve(root, action string, remaining int64, status EmergencyReserveStatus, allocate func(*os.File) error) (result EmergencyReserveStatus, err error) {
	path := filepath.Join(root, emergencyReserveName)
	flags := os.O_RDWR | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if !status.Enabled {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return status, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	// 空の印を先に永続化する。中断した確保を未導入扱いに戻さない。
	if err = f.Sync(); err != nil {
		return status, err
	}
	if err = store.SyncDirectory(root); err != nil {
		return status, err
	}
	if action == "prepare" {
		err = allocate(f)
	} else if status.Bytes > remaining {
		err = f.Truncate(remaining)
	}
	if err != nil {
		return status, err
	}
	if err = f.Sync(); err != nil {
		return status, err
	}
	status, err = inspectEmergencyReserve(root)
	if err == nil && action == "prepare" && !status.Ready {
		err = errors.New("emergency reserve allocation incomplete")
	}
	return status, err
}

// RemainingMiB は管理画面向けの予約ファイル残量。実割当の完了判定はReadyを使う。
func (s EmergencyReserveStatus) RemainingMiB() int64 { return s.Bytes >> 20 }
