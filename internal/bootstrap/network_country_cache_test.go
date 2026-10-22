// 検証済み国表の再利用が、破損拒否・版の分離・有界保持を維持することを検査する。
package bootstrap

import (
	"net/netip"
	"oimobbs/internal/identity"
	"sync"
	"testing"
)

func TestCountryDecodeCache(t *testing.T) {
	var cache countryDecodeCache
	encoded := func(code string) string {
		t.Helper()
		value, err := encodeCountries([]identity.CountryNetwork{{Prefix: netip.MustParsePrefix("192.0.2.0/24"), Code: code}})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	first := encoded("JP")
	table, count, err := cache.decode(first)
	if err != nil || count != 1 {
		t.Fatal(count, err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			got, count, err := cache.decode(first)
			if err != nil || got != table || count != 1 {
				t.Error("同じ検証済み表を再構築した", err)
			}
		})
	}
	wg.Wait()
	if _, _, err := cache.decode(first + "!"); err == nil {
		t.Fatal("破損をcacheで受理した")
	}
	for _, code := range []string{"US", "DE"} {
		got, _, err := cache.decode(encoded(code))
		if err != nil {
			t.Fatal(err)
		}
		actual, _, _ := got.Match(netip.MustParseAddr("192.0.2.1"))
		if actual != code {
			t.Fatal("別の表を混同した", actual)
		}
	}
	reloaded, _, err := cache.decode(first)
	if err != nil || reloaded == table {
		t.Fatal("2版を超えて保持した", err)
	}
	code, _, _ := table.Match(netip.MustParseAddr("192.0.2.1"))
	if code != "JP" {
		t.Fatal("交換前の表が変化した")
	}
}
