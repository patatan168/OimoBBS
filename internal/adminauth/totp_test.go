// RFCの既知ベクトルと時刻境界・使い回し・入力形式を検証する。
package adminauth

import (
	"testing"
	"time"
)

func TestTOTPRFCVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		at   int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		if next, ok := VerifyTOTP(secret, tc.want[2:], 0, time.Unix(tc.at, 0)); !ok || next != uint64(tc.at/30)+1 {
			t.Fatal("RFC six-digit verification", tc.at)
		}
		if got := totpCode(secret, uint64(tc.at/30), 8); got != tc.want {
			t.Fatalf("at %d: %s != %s", tc.at, got, tc.want)
		}
	}
}

func TestTOTPWindowReplayAndFormat(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1800000000, 0)
	step := uint64(now.Unix() / 30)
	for _, delta := range []int64{-2, -1, 0, 1, 2} {
		code := totpCode(secret, uint64(int64(step)+delta), 6)
		next, ok := VerifyTOTP(secret, code, 0, now)
		if ok != (delta >= -1 && delta <= 1) {
			t.Fatal("window", delta, ok)
		}
		if ok {
			if next != uint64(int64(step)+delta)+1 {
				t.Fatal("wrong watermark")
			}
			if _, ok := VerifyTOTP(secret, code, next, now); ok {
				t.Fatal("replayed code", delta)
			}
		}
	}
	for _, code := range []string{"", "12345", "1234567", "１２３４５６", " 12345", "12a456"} {
		if _, ok := VerifyTOTP(secret, code, 0, now); ok {
			t.Fatal("invalid code accepted")
		}
	}
	if _, ok := VerifyTOTP(secret, totpCode(secret, step, 6), step+2, now); ok {
		t.Fatal("clock rollback accepted")
	}
	if _, ok := VerifyTOTP(secret, "123456", 0, time.Unix(-1, 0)); ok {
		t.Fatal("pre-epoch accepted")
	}
	if _, ok := VerifyTOTP([]byte("short"), "123456", 0, now); ok {
		t.Fatal("invalid secret accepted")
	}
}
