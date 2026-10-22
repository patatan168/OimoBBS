//go:build linux

// Linux filesystemの総容量とサービスUIDが使える空き容量を取得する。
package platform

import (
	"errors"
	"math"
	"syscall"
)

// DiskSpace はroot専用予約領域を空き容量に含めない。
type DiskSpace struct{ Total, Available uint64 }

// Space は実filesystemの容量をbyteで返す。異常値や乗算overflowは拒否する。
func Space(path string) (DiskSpace, error) {
	var stat syscall.Statfs_t
	if e := syscall.Statfs(path, &stat); e != nil {
		return DiskSpace{}, e
	}
	return diskSpace(stat.Blocks, stat.Bavail, stat.Bsize)
}
func diskSpace(blocks, available uint64, size int64) (DiskSpace, error) {
	if size <= 0 || available > blocks || blocks > math.MaxUint64/uint64(size) {
		return DiskSpace{}, errors.New("invalid filesystem capacity")
	}
	return DiskSpace{blocks * uint64(size), available * uint64(size)}, nil
}
