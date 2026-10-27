// JDim公開試験の既知結果と独立したDES crypt vectorsを照合する。
package identity

import "testing"

func TestTripVectors(t *testing.T) {
	for _, v := range [][2]string{{"", ""}, {"A", "hRJ9Ya./t."}, {"hellowo", "/wfpxFEFeQ"}, {"hellowor", "d75etXAowg"}, {"helloworld!", "d75etXAowg"}, {"四字熟語", "sX.SlNvMe."}, {"#0123456789", "RTDIJZhD3g"}, {"$0123456789", "46g6cHndYk"}, {"helloworld!?", "xwumaTFfu1OK"}, {"jdimprovedproject", "Y7G9gYfXrr6."}, {"#0123456789abcdef", "ClNHFHdYIw"}, {"#あいうえおか", "???"}, {"$将来の拡張用", "???"}} {
		got, e := Trip(v[0])
		if e != nil || got != v[1] {
			t.Errorf("vector %q got %s want %s err %v", v[0], got, v[1], e)
		}
	}
}
func TestCrypt(t *testing.T) {
	if s := desCrypt([]byte("password"), "ab"); s != "abJnggxhB/yWI" {
		t.Fatal(s)
	}
	if s := desCrypt(nil, ".."); s != "..X8NBuQ4l6uQ" {
		t.Fatal(s)
	}
}

// 追加値はLinux libcryptの独立計算と照合。Go実装の出力から期待値を作らない。
func TestShortSaltAndRawNUL(t *testing.T) {
	for _, v := range [][2]string{{"AA", "Emjcf.lfLU"}, {"#0001020304050607", "8NBuQ4l6uQ"}, {"#4100424344454647ab", "wkuZdL5N8o"}, {"#0123456789abcdefA", "VcST/SPkC2"}, {"#0123456789abcdefAz", "LrkfFhWMKI"}} {
		got, e := Trip(v[0])
		if e != nil || got != v[1] {
			t.Errorf("%q got %q want %q: %v", v[0], got, v[1], e)
		}
	}
}
