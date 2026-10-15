// Linuxの空き容量換算とoverflow拒否を確認する。
package platform

import (
	"math"
	"testing"
)

func TestDiskSpace(t *testing.T) {
	for _, v := range []struct {
		blocks, free uint64
		size         int64
	}{{1, 2, 4096}, {1, 1, 0}, {1, 1, -1}, {math.MaxUint64, 1, 4096}} {
		if _, e := diskSpace(v.blocks, v.free, v.size); e == nil {
			t.Fatal(v)
		}
	}
	s, e := diskSpace(10, 3, 4096)
	if e != nil || s.Total != 40960 || s.Available != 12288 {
		t.Fatal(s, e)
	}
	s, e = Space(t.TempDir())
	if e != nil || s.Total == 0 || s.Available > s.Total {
		t.Fatal(s, e)
	}
}
