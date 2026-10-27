// 空主体の除去で、巡回順と次の主体が従来の全走査と一致することを検査する。
package delivery

import (
	"net/netip"
	"slices"
	"testing"
)

func TestPrunePreservesEveryCursorPosition(t *testing.T) {
	for _, count := range []int{1, 2, 8, 64} {
		for cursor := 0; cursor < count; cursor++ {
			for remove := 0; remove < count; remove++ {
				s := &Scheduler{subjects: map[netip.Addr]*subject{}, cursor: cursor}
				for i := 0; i < count; i++ {
					ip := netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)})
					s.order = append(s.order, ip)
					s.subjects[ip] = &subject{active: 1}
				}
				key := s.order[remove]
				s.subjects[key].active = 0
				want := slices.Clone(s.order)
				want = append(want[:remove], want[remove+1:]...)
				next := s.order[cursor]
				wantCursor := 0
				for i, ip := range want {
					if ip == next {
						wantCursor = i
						break
					}
				}
				s.pruneLocked(key)
				if !slices.Equal(s.order, want) || s.cursor != wantCursor || len(s.subjects) != count-1 {
					t.Fatal(count, cursor, remove, s.cursor, wantCursor)
				}
			}
		}
	}
}
