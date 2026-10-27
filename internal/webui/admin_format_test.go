// 管理画面の単位換算でIEC容量と10進帯域を取り違えないことを確認する。
package webui

import "testing"

func TestAdminDisplayUnits(t *testing.T) {
	for _, tc := range []struct {
		bytes uint64
		want  string
	}{{0, "0 B"}, {1023, "1023 B"}, {1024, "1.0 KiB"}, {3 << 29, "1.5 GiB"}, {^uint64(0), "16.0 EiB"}} {
		if got := formatBytes(tc.bytes); got != tc.want {
			t.Fatalf("%d: %s != %s", tc.bytes, got, tc.want)
		}
	}
	if got := formatMbps(80_000_000); got != "80.0 Mbps" {
		t.Fatal(got)
	}
}
