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
