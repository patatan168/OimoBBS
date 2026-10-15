// 保存圧縮の年齢・追記・時間境界と時計逆行を検証する。
package store

import (
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestPackMaintenancePolicy(t *testing.T) {
	day := domain.Time(24 * time.Hour)
	created := domain.Time(1_700_000_000_000_000_000)
	base := PackMaintenanceInfo{Created: created, Expires: created + 180*day, LastPacked: created, Generation: 2, Level: 1, Codec: 2}
	cases := []struct {
		name       string
		age        domain.Time
		bytes, ops uint64
		level      uint8
		want       string
	}{
		{"fresh", day - 1, 1, 1, 1, ""}, {"daily", day, 1, 1, 1, "elapsed"},
		{"idle", day, 0, 0, 1, ""}, {"bytes", 0, 4 << 20, 1, 1, "bytes"}, {"below bytes", 0, (4 << 20) - 1, 1, 1, ""},
		{"operations", 0, 1, 1024, 1, "operations"}, {"below operations", 0, 1, 1023, 1, ""},
		{"seven days", 7 * day, 0, 0, 1, "level"}, {"before seven", 7*day - 1, 0, 0, 1, ""},
		{"thirty days", 30 * day, 0, 0, 6, "level"}, {"before thirty", 30*day - 1, 0, 0, 6, ""},
		{"expired", 180 * day, 4 << 20, 1024, 1, "expired"}, {"backwards", -day, 1, 1, 6, ""},
		{"strong level", day, 1, 1, 9, "elapsed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			s.DeltaBytes = tc.bytes
			s.DeltaOperations = tc.ops
			s.Level = tc.level
			got := s.Decision(created + tc.age)
			if got.Reason != tc.want {
				t.Fatal(got)
			}
			if got.Compact && got.Level < s.Level {
				t.Fatal("level downgraded")
			}
		})
	}
	base.Generation = 1
	base.Level = 0
	base.DeltaOperations = 1
	base.DeltaBytes = 100
	if d := base.Decision(created + day); !d.Compact || d.Level != 1 {
		t.Fatal(d)
	}
	base.LastPacked = created + 2*day
	if d := base.Decision(created + day); d.Compact {
		t.Fatal("rollback elapsed", d)
	}
}
