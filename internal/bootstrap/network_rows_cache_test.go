// 検証済み圧縮回線表の再利用でも、破損拒否と返却配列の独立性を維持する。
package bootstrap

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"oimobbs/internal/identity"
)

func TestNetworkRowCacheIsolationAndRejection(t *testing.T) {
	var cache networkRowsCache
	rows := networkRows{{CIDR: "192.0.2.0/24", Kind: "fixed", Label: "ﾜｯﾁｮｲ", Suffix: "0", Provider: "sonet"}}
	raw, err := json.Marshal([]identity.NetworkClass(rows))
	if err != nil {
		t.Fatal(err)
	}
	packed, err := compressNetworkData(raw)
	if err != nil {
		t.Fatal(err)
	}
	first, err := cache.decode(packed)
	if err != nil || !reflect.DeepEqual(first, rows) {
		t.Fatal("initial decode", first, err)
	}
	first[0].CIDR = "198.51.100.0/24"
	second, err := cache.decode(packed)
	if err != nil || !reflect.DeepEqual(second, rows) {
		t.Fatal("returned rows changed cached validation", second, err)
	}
	for _, invalid := range []string{"null", string(raw) + "[]", `[{"cidr":"192.0.2.1/24","kind":"fixed","label":"ﾜｯﾁｮｲ","suffix":"0","provider":"sonet"}]`, `[{"cidr":"192.0.2.0/24","kind":"fixed","label":"ﾜｯﾁｮｲ","suffix":"0","provider":"sonet","extra":true}]`, strings.Repeat(" ", networkRowsJSONLimit+1)} {
		bad, err := compressNetworkData([]byte(invalid))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = cache.decode(bad); err == nil {
			t.Fatal("accepted invalid compressed rows")
		}
	}
	if _, err = cache.decode(packed + "!"); err == nil {
		t.Fatal("accepted changed encoded data")
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 8 {
				got, err := cache.decode(packed)
				if err != nil || !reflect.DeepEqual(got, rows) {
					t.Error("concurrent decode", err)
					return
				}
				got[0].Provider = "changed"
			}
		})
	}
	workers.Wait()
}

func TestNetworkRowCacheReplacement(t *testing.T) {
	var cache networkRowsCache
	for i := range 4 {
		raw := fmt.Sprintf(`[{"cidr":"192.0.%d.0/24","kind":"fixed","label":"ﾜｯﾁｮｲ","suffix":"0","provider":"sonet"}]`, i)
		packed, err := compressNetworkData([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		rows, err := cache.decode(packed)
		if err != nil || len(rows) != 1 || rows[0].CIDR != fmt.Sprintf("192.0.%d.0/24", i) {
			t.Fatal("stale rows after replacement", rows, err)
		}
	}
}
