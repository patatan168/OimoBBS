// 識別HMACと暦月期限を設計の独立期待値と照合する。
package identity

import (
	"encoding/hex"
	"net/netip"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestDailyVector(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	b, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	var board domain.ID
	copy(board[:], b)
	now, _ := time.Parse(time.RFC3339, "2026-09-27T12:00:00+09:00")
	s, e := DailyID(key, board, now, netip.MustParseAddr("::ffff:192.0.2.1"))
	if e != nil || s != "rLxlKF/0" {
		t.Fatal(s, e)
	}
}
func TestMonthClamp(t *testing.T) {
	for _, v := range [][2]string{{"2026-08-31T12:00:00+09:00", "2027-02-28T12:00:00+09:00"}, {"2023-08-31T12:00:00+09:00", "2024-02-29T12:00:00+09:00"}} {
		at, _ := time.Parse(time.RFC3339, v[0])
		if got := domain.SixMonths(at).Format(time.RFC3339); got != v[1] {
			t.Fatal(got)
		}
	}
}
