// 圧縮の再利用が入力所有権・同時実行・二版上限・保存byte互換を守ることを検証する。
package bootstrap

import (
	"bytes"
	"sync"
	"testing"
)

func TestNetworkCompressionCache(t *testing.T) {
	var cache networkCompressionCache
	raw := bytes.Repeat([]byte("network"), 1000)
	want, err := compressNetworkData(raw)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			got, err := cache.compress(raw)
			if err != nil || got != want {
				t.Error("圧縮byteが変化した", err)
			}
		})
	}
	workers.Wait()
	raw[0] = 'N'
	changed, err := cache.compress(raw)
	if err != nil || changed == want {
		t.Fatal("変更された入力を同じと扱った", err)
	}
	decoded, err := decompressNetworkData(want, 10000)
	if err != nil || decoded[0] != 'n' {
		t.Fatal("旧版が変更された", err)
	}
	third := []byte("third")
	if _, err := cache.compress(third); err != nil {
		t.Fatal(err)
	}
	for _, entry := range cache.entries {
		if entry.encoded == want {
			t.Fatal("二版を超えて保持した")
		}
	}
}
