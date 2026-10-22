// Python標準hmacで独立計算したLP導出値と、用途・ID分離を検証する。
package identity

import "testing"

func TestDeriveKey(t *testing.T) {
	master := make([]byte, 32)
	for i := range master {
		master[i] = byte(i)
	}
	key, err := DeriveKey(master, "csrf", 6)
	if err != nil || key.String() != "4658827e6d4053cf31071a19da7a4c115a3044c89973f90727b93af9d45db581" {
		t.Fatal(key, err)
	}
	other, err := DeriveKey(master, "confirm", 6)
	if err != nil || key == other {
		t.Fatal("purpose not separated")
	}
	other, err = DeriveKey(master, "csrf", 7)
	if err != nil || key == other {
		t.Fatal("key ID not separated")
	}
	if _, err = DeriveKey(master, "csrf", 0); err == nil {
		t.Fatal("zero ID accepted")
	}
	if _, err = DeriveKey(master, "csrf/../", 1); err == nil {
		t.Fatal("invalid purpose accepted")
	}
	if _, err = DeriveKey(master[:31], "csrf", 1); err == nil {
		t.Fatal("short master accepted")
	}
}
