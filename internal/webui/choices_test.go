// 旧追加フラグを含め、選択表示と実際の公開内容が一致することを検査する。
package webui

import "testing"

func TestDisplayMode(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		hash, ip bool
		want     string
	}{
		{"vvvvv", false, true, "vvvvvv"}, {"none", true, true, "vvvvvv"}, {"vvvv", true, false, "vvvvvv"}, {"vvv", false, true, "vvvv"}, {"none", true, false, "vvvvv"}, {"feature", false, false, "feature"}, {"vvvvv", false, false, "vvvvv"},
	} {
		if got := displayMode(tc.mode, tc.hash, tc.ip); got != tc.want {
			t.Fatalf("%+v: %s", tc, got)
		}
	}
}
