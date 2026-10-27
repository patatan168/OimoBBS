// 投稿・本文反映・pack・backupの未使用予約を同じ台帳で照合し、容量の二重使用を防ぐ。
package bootstrap

// reservedDiskBytes はpackResourcesMuの内側で全用途の予約を合算し、overflowでは飽和する。
func (r *Repository) reservedDiskBytes() uint64 {
	var total uint64
	for _, size := range [...]uint64{r.packReserved, r.postReserved, r.postBodyReserved, r.backupReserved} {
		if size > ^uint64(0)-total {
			return ^uint64(0)
		}
		total += size
	}
	return total
}
