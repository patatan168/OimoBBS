// Linuxの物理メモリ・cgroup・Go管理領域から、GC目標と受付の余裕を求める。
package platform

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"syscall"
)

// ConfigureRuntime は物理メモリとcgroupの小さい方の75%をGoのsoft limitにする。
// GOMEMLIMITの明示指定と既存のより小さいlimitを優先する。CPUの自動追従はGoに任せる。
func ConfigureRuntime() {
	if _, explicit := os.LookupEnv("GOMEMLIMIT"); explicit {
		return
	}
	limit := physicalMemoryLimit()
	if container := containerMemoryLimit(os.ReadFile); container > 0 && (limit == 0 || container < limit) {
		limit = container
	}
	if limit == 0 {
		return
	}
	budget := limit - limit/4
	if current := debug.SetMemoryLimit(-1); budget < current {
		debug.SetMemoryLimit(budget)
	}
}

// MemoryState はGo管理領域とOS・cgroupの余裕を合わせた受付判断用の観測値。
// Headroomは空き容量の観測であり、同時要求の予約は利用側で別途管理する。
type MemoryState struct {
	Limit     uint64 `json:"limit_bytes"`
	Managed   uint64 `json:"managed_bytes"`
	Headroom  uint64 `json:"headroom_bytes"`
	Reusable  uint64 `json:"reusable_bytes"`
	Live      uint64 `json:"live_heap_bytes"`
	Allocated uint64 `json:"allocated_heap_bytes"`
}

// ObserveMemory はsoft limit、Go管理領域、祖先cgroup、ホストの空きを照合する。
// ファイル読取りを伴うため要求ごとではなく監視周期で呼ぶ。
func ObserveMemory() MemoryState {
	samples := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}, {Name: "/memory/classes/heap/free:bytes"}, {Name: "/gc/heap/live:bytes"}, {Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(samples)
	managed := samples[0].Value.Uint64() - samples[1].Value.Uint64()
	state := observeMemory(os.ReadFile, uint64(debug.SetMemoryLimit(-1)), managed, min(managed, samples[2].Value.Uint64()), physicalMemoryLimit())
	state.Live = samples[3].Value.Uint64()
	state.Allocated = samples[4].Value.Uint64()
	return state
}

func observeMemory(read func(string) ([]byte, error), limit, managed, reusable uint64, physical int64) MemoryState {
	if physical > 0 {
		limit = min(limit, uint64(physical-physical/4))
	}
	reusable = min(reusable, managed)
	working := managed - reusable
	state := MemoryState{Limit: limit, Managed: managed, Reusable: reusable, Headroom: remainingMemory(limit, working)}
	for _, path := range containerMemoryPaths(read) {
		budget, headroom, ok := cgroupMemoryBudget(read, path, reusable)
		if ok {
			state.Limit = min(state.Limit, budget)
			state.Headroom = min(state.Headroom, headroom)
		}
	}
	state.Headroom = min(state.Headroom, remainingMemory(state.Limit, working))
	if raw, err := read("/proc/meminfo"); err == nil {
		if available, ok := hostAvailableMemory(raw); ok {
			state.Headroom = min(state.Headroom, available+reusable)
		}
	}
	return state
}

// cgroupMemoryBudget は同じ階層の上限と使用量を照合し、回収できるページを除く。
func cgroupMemoryBudget(read func(string) ([]byte, error), path string, reusable uint64) (uint64, uint64, bool) {
	raw, err := read(path)
	if err != nil {
		return 0, 0, false
	}
	maximum, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || maximum == 0 || maximum >= 1<<60 {
		return 0, 0, false
	}
	headroom := ^uint64(0)
	currentPath := strings.ReplaceAll(strings.ReplaceAll(path, "memory.max", "memory.current"), "memory.limit_in_bytes", "memory.usage_in_bytes")
	if current, err := read(currentPath); err == nil {
		if used, err := strconv.ParseUint(strings.TrimSpace(string(current)), 10, 64); err == nil {
			stat, _ := read(filepath.Join(filepath.Dir(path), "memory.stat"))
			used -= min(used, inactiveFileMemory(stat))
			used -= min(used, reusable)
			headroom = remainingMemory(maximum, used)
		}
	}
	return maximum - maximum/4, headroom, true
}

func inactiveFileMemory(raw []byte) uint64 {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && (fields[0] == "inactive_file" || fields[0] == "total_inactive_file") {
			bytes, _ := strconv.ParseUint(fields[1], 10, 64)
			return bytes
		}
	}
	return 0
}

func hostAvailableMemory(raw []byte) (uint64, bool) {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "MemAvailable:" {
			kib, err := strconv.ParseUint(fields[1], 10, 64)
			if err == nil && kib < 1<<50 {
				return kib << 10, true
			}
		}
	}
	return 0, false
}

func remainingMemory(limit, used uint64) uint64 {
	if used >= limit {
		return 0
	}
	return limit - used
}

func physicalMemoryLimit() int64 {
	var info syscall.Sysinfo_t
	if syscall.Sysinfo(&info) != nil || info.Unit == 0 || info.Totalram > ((1<<63)-1)/uint64(info.Unit) {
		return 0
	}
	return int64(info.Totalram * uint64(info.Unit))
}

// containerMemoryLimit はv2の祖先制限とv1の固定パスを読み、無制限・読取不能を除く。
func containerMemoryLimit(read func(string) ([]byte, error)) int64 {
	var limit int64
	for _, path := range containerMemoryPaths(read) {
		raw, err := read(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		if err == nil && value > 0 && value < 1<<60 && (limit == 0 || value < limit) {
			limit = value
		}
	}
	return limit
}

func containerMemoryPaths(read func(string) ([]byte, error)) []string {
	paths := []string{"/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"}
	if raw, err := read("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			if !strings.HasPrefix(line, "0::/") {
				continue
			}
			root := "/sys/fs/cgroup"
			path := filepath.Join(root, strings.TrimPrefix(line, "0::"))
			for path != root && strings.HasPrefix(path, root+"/") {
				paths = append(paths, filepath.Join(path, "memory.max"))
				path = filepath.Dir(path)
			}
		}
	}
	return paths
}
