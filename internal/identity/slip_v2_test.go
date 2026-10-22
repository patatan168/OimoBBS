// 独立生成した既知値と区画ごとの変化条件で独自ワッチョイを検査する。
package identity

import (
	"encoding/hex"
	"net/netip"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestSlipV2Parts(t *testing.T) {
	var netKey, uaKey domain.Hash
	for i := range netKey {
		netKey[i], uaKey[i] = byte(i), byte(i+32)
	}
	var board, cookie domain.ID
	b, _ := hex.DecodeString("00112233445566778899aabbccddeeff")
	c, _ := hex.DecodeString("102132435465768798a9bacbdcedfe0f")
	copy(board[:], b)
	copy(cookie[:], c)
	now := time.Date(2026, 10, 10, 0, 0, 0, 0, domain.JST)
	get := func(board domain.ID, at time.Time, ip, provider string, id domain.ID, ua string) string {
		t.Helper()
		v, err := Slip(netKey[:], uaKey[:], board, at, netip.MustParseAddr(ip), provider, id, ua)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	base := get(board, now, "192.0.2.1", "ocn", cookie, "Monazilla/1.00 (Android 16; Pixel 9)")
	// Pythonのhmac/hashlib/structによる独立計算値。製品のminorとコメントは入力しない。
	if base != "h8xE-boYY" {
		t.Fatal(base)
	}
	for _, ip := range []string{"192.0.2.254", "::ffff:192.0.2.1"} {
		if get(board, now, ip, "ocn", cookie, "Monazilla/1.99 (different)") != base {
			t.Fatal("same /24 or UA classification changed")
		}
	}
	parts := func(v string) [4]string { return [4]string{v[:2], v[2:4], v[5:7], v[7:]} }
	original := parts(base)
	otherCookie, otherBoard := cookie, board
	otherCookie[0]++
	otherBoard[0]++
	for _, tc := range []struct {
		name, value string
		changed     [4]bool
	}{
		{"network", get(board, now, "192.0.3.1", "ocn", cookie, "Monazilla/1"), [4]bool{true, false, false, false}},
		{"provider", get(board, now, "192.0.2.1", "iij", cookie, "Monazilla/1"), [4]bool{false, true, false, false}},
		{"cookie", get(board, now, "192.0.2.1", "ocn", otherCookie, "Monazilla/1"), [4]bool{false, false, true, false}},
		{"ua", get(board, now, "192.0.2.1", "ocn", cookie, "Monazilla/2"), [4]bool{false, false, false, true}},
		{"week", get(board, now.AddDate(0, 0, 7), "192.0.2.1", "ocn", cookie, "Monazilla/1"), [4]bool{true, false, false, true}},
		{"board", get(otherBoard, now, "192.0.2.1", "ocn", cookie, "Monazilla/1"), [4]bool{true, true, true, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := parts(tc.value)
			for i := range got {
				if (got[i] != original[i]) != tc.changed[i] {
					t.Fatal(original, got)
				}
			}
		})
	}
	before := time.Date(2026, 10, 15, 0, 0, 0, 0, domain.JST).Add(-time.Nanosecond)
	if get(board, before, "192.0.2.1", "ocn", cookie, "Monazilla/1") != base {
		t.Fatal("changed before Thursday")
	}
	if get(board, before.Add(time.Nanosecond), "192.0.2.1", "ocn", cookie, "Monazilla/1") == base {
		t.Fatal("Thursday boundary lost")
	}
	a := get(board, now, "2001:db8:1:2::1", "ocn", cookie, "")
	if get(board, now, "2001:db8:1:2:ffff::1", "ocn", cookie, "") != a {
		t.Fatal("same IPv6 /64 changed")
	}
	if get(board, now, "2001:db8:1:3::1", "ocn", cookie, "")[:2] == a[:2] {
		t.Fatal("IPv6 /64 ignored")
	}
	if _, err := Slip(netKey[:], uaKey[:], board, now, netip.MustParseAddr("192.0.2.1"), "ocn", domain.ID{}, ""); err == nil {
		t.Fatal("missing cookie accepted")
	}
}
