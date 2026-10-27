// 大きい登録国表の再検証時に、内容が同一の検証済み不変索引を最大二版だけ共有する。
package bootstrap

import (
	"oimobbs/internal/identity"
	"sync"
)

type countryDecodeEntry struct {
	value string
	table *identity.CountryTable
	count int
}

type countryDecodeCache struct {
	mu      sync.Mutex
	entries [2]countryDecodeEntry
}

var decodedCountries countryDecodeCache

// decode は同じ完全な保存byteだけを共有する。未検証・破損値は保持せず、旧参照は変更しない。
// 最大二版のLRUで更新前後の表を保持し、同時missの重複展開も防ぐ。
func (c *countryDecodeCache) decode(value string) (*identity.CountryTable, int, error) {
	if value == "" {
		return nil, 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for index, entry := range c.entries {
		if entry.value == value {
			if index == 1 {
				c.entries[0], c.entries[1] = c.entries[1], c.entries[0]
			}
			return entry.table, entry.count, nil
		}
	}
	table, count, err := decodeCountriesUncached(value)
	if err != nil {
		return nil, 0, err
	}
	c.entries[1], c.entries[0] = c.entries[0], countryDecodeEntry{value, table, count}
	return table, count, nil
}
