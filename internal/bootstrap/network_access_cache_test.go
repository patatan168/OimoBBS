// 索引共有時の入力変更・未取得family・失敗・上書きの分離を検証する。
package bootstrap

import (
	"net/netip"
	"oimobbs/internal/identity"
	"sync"
	"testing"
)

func TestNetworkAccessCache(t *testing.T) {
	var cache networkAccessCache
	data := networkAccessData{Japan: []string{"192.0.2.0/24"}, VPN4: []string{"198.51.100.0/24"}}
	first, err := cache.compile(&data)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			got, err := cache.compile(&data)
			if err != nil || got != first {
				t.Error("同じ表を再構築した", err)
			}
		})
	}
	workers.Wait()
	data.Japan[0] = "203.0.113.0/24"
	second, err := cache.compile(&data)
	if err != nil || second == first {
		t.Fatal("変更を見落とした", err)
	}
	if _, ok := first.Japan.Match(netip.MustParseAddr("192.0.2.1")); !ok {
		t.Fatal("旧索引が変化した")
	}
	data.VPN6 = []string{}
	if _, err := cache.compile(&data); err == nil {
		t.Fatal("未取得と不正な空配列を混同した")
	}
	data.VPN6 = nil
	data.VPN4[0] = "bad prefix"
	if _, err := cache.compile(&data); err == nil {
		t.Fatal("破損を受理した")
	}
	data.VPN4[0] = "198.51.100.0/24"
	overrides := []identity.AccessOverride{{CIDR: "192.0.2.0/24", Country: "jp", VPN: "auto"}}
	a, err := compileAccessData(&data, overrides)
	if err != nil {
		t.Fatal(err)
	}
	a.Overrides[0].Country = "foreign"
	b, err := compileAccessData(&data, overrides)
	if err != nil || b.Overrides[0].Country != "jp" || overrides[0].Country != "jp" {
		t.Fatal("上書きを共有した", err)
	}
}
