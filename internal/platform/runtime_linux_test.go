// コンテナの階層・無制限・未対応環境でもメモリ上限を誤認しないことを検査する。
package platform

import (
	"os"
	"testing"
)

func TestContainerMemoryLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  int64
	}{
		{"docker-v2", map[string]string{"/sys/fs/cgroup/memory.max": "1073741824\n"}, 1 << 30},
		{"nested-parent", map[string]string{"/proc/self/cgroup": "0::/services/bbs\n", "/sys/fs/cgroup/memory.max": "max", "/sys/fs/cgroup/services/memory.max": "536870912", "/sys/fs/cgroup/services/bbs/memory.max": "1073741824"}, 512 << 20},
		{"v1", map[string]string{"/sys/fs/cgroup/memory/memory.limit_in_bytes": "268435456"}, 256 << 20},
		{"unlimited", map[string]string{"/sys/fs/cgroup/memory.max": "max", "/sys/fs/cgroup/memory/memory.limit_in_bytes": "9223372036854771712"}, 0},
		{"invalid", map[string]string{"/sys/fs/cgroup/memory.max": "-1"}, 0},
		{"absent", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if value, ok := tc.files[path]; ok {
					return []byte(value), nil
				}
				return nil, os.ErrNotExist
			}
			if got := containerMemoryLimit(read); got != tc.want {
				t.Fatalf("limit=%d want=%d", got, tc.want)
			}
		})
	}
}

func TestObserveMemoryPressureSources(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		files                   map[string]string
		limit, managed          uint64
		physical                int64
		wantLimit, wantHeadroom uint64
	}{
		{name: "managed-limit", limit: 384 << 20, managed: 360 << 20, physical: 1 << 30, wantLimit: 384 << 20, wantHeadroom: 24 << 20},
		{name: "physical-limit", limit: 1 << 62, managed: 100 << 20, physical: 256 << 20, wantLimit: 192 << 20, wantHeadroom: 92 << 20},
		{name: "reclaimable-file-cache", files: map[string]string{"/sys/fs/cgroup/memory.max": "268435456", "/sys/fs/cgroup/memory.current": "262144000", "/sys/fs/cgroup/memory.stat": "inactive_file 83886080\n"}, limit: 384 << 20, managed: 100 << 20, physical: 1 << 30, wantLimit: 192 << 20, wantHeadroom: 86 << 20},
		{name: "ancestor-pressure", files: map[string]string{"/proc/self/cgroup": "0::/parent/child", "/sys/fs/cgroup/memory.max": "max", "/sys/fs/cgroup/parent/memory.max": "536870912", "/sys/fs/cgroup/parent/memory.current": "503316480", "/sys/fs/cgroup/parent/child/memory.max": "268435456", "/sys/fs/cgroup/parent/child/memory.current": "83886080"}, limit: 384 << 20, managed: 100 << 20, physical: 1 << 30, wantLimit: 192 << 20, wantHeadroom: 32 << 20},
		{name: "host-pressure", files: map[string]string{"/proc/meminfo": "MemAvailable: 16384 kB\n"}, limit: 384 << 20, managed: 100 << 20, physical: 1 << 30, wantLimit: 384 << 20, wantHeadroom: 16 << 20},
		{name: "exhausted", limit: 192 << 20, managed: 200 << 20, physical: 256 << 20, wantLimit: 192 << 20, wantHeadroom: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			read := func(path string) ([]byte, error) {
				if raw, ok := tc.files[path]; ok {
					return []byte(raw), nil
				}
				return nil, os.ErrNotExist
			}
			state := observeMemory(read, tc.limit, tc.managed, 0, tc.physical)
			if state.Limit != tc.wantLimit || state.Headroom != tc.wantHeadroom {
				t.Fatalf("%+v want limit=%d headroom=%d", state, tc.wantLimit, tc.wantHeadroom)
			}
		})
	}
}

// Goの空きページは追加のOS割当なしで使えるので、保持メモリだけで受付を止めない。
func TestObserveMemoryReusesIdleHeap(t *testing.T) {
	read := func(path string) ([]byte, error) {
		switch path {
		case "/sys/fs/cgroup/memory.max":
			return []byte("268435456"), nil
		case "/sys/fs/cgroup/memory.current":
			return []byte("230686720"), nil
		}
		return nil, os.ErrNotExist
	}
	state := observeMemory(read, 192<<20, 180<<20, 80<<20, 256<<20)
	if state.Headroom != 92<<20 || state.Reusable != 80<<20 {
		t.Fatal("idle heap treated as active work", state)
	}
}
