// Linuxコンテナのメモリ制限に合わせ、Goヒープ以外の領域にも余裕を残す。
package platform

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
)

// ConfigureRuntime はcgroupの最小メモリ上限の75%をGoのsoft limitにする。
// GOMEMLIMITの明示指定と既存のより小さいlimitを優先する。CPUの自動追従はGoに任せる。
func ConfigureRuntime() {
	if _, explicit := os.LookupEnv("GOMEMLIMIT"); explicit {
		return
	}
	limit := containerMemoryLimit(os.ReadFile)
	if limit == 0 {
		return
	}
	budget := limit - limit/4
	if current := debug.SetMemoryLimit(-1); budget < current {
		debug.SetMemoryLimit(budget)
	}
}

// containerMemoryLimit はv2の祖先制限とv1の固定パスを読み、無制限・読取不能を除く。
func containerMemoryLimit(read func(string) ([]byte, error)) int64 {
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
	var limit int64
	for _, path := range paths {
		raw, err := read(path)
		if err != nil {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
		// v1の無制限値はほぼMaxInt64。実用上あり得ない値をbudgetへ変換しない。
		if err == nil && value > 0 && value < 1<<60 && (limit == 0 || value < limit) {
			limit = value
		}
	}
	return limit
}
