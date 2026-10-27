// 同じ登録国・日本・VPN表の検証済み不変索引を二版まで共有する。
package bootstrap

import (
	"oimobbs/internal/identity"
	"slices"
	"sync"
)

type networkAccessCacheEntry struct {
	data  networkAccessData
	index *identity.AccessIndex
}
type networkAccessCache struct {
	mu      sync.Mutex
	entries [2]networkAccessCacheEntry
}

var compiledNetworkAccess networkAccessCache

// compile は全入力の完全一致だけで再利用する。運営の上書きは含めず、呼出元が別途検証する。
func (c *networkAccessCache) compile(data *networkAccessData) (*identity.AccessIndex, error) {
	if data == nil {
		return &identity.AccessIndex{}, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, entry := range c.entries {
		if entry.index != nil && equalNetworkAccessData(entry.data, *data) {
			if i == 1 {
				c.entries[0], c.entries[1] = c.entries[1], c.entries[0]
			}
			return entry.index, nil
		}
	}
	index, err := compileAccessDataUncached(data)
	if err != nil {
		return nil, err
	}
	copyData := networkAccessData{Countries: data.Countries, Japan: slices.Clone(data.Japan), VPN4: slices.Clone(data.VPN4), VPN6: slices.Clone(data.VPN6)}
	c.entries[1], c.entries[0] = c.entries[0], networkAccessCacheEntry{copyData, index}
	return index, nil
}

// equalNetworkAccessData は未取得nilと取得済み空配列も区別する。
func equalNetworkAccessData(a, b networkAccessData) bool {
	return a.Countries == b.Countries && (a.Japan == nil) == (b.Japan == nil) && (a.VPN4 == nil) == (b.VPN4 == nil) && (a.VPN6 == nil) == (b.VPN6 == nil) && slices.Equal(a.Japan, b.Japan) && slices.Equal(a.VPN4, b.VPN4) && slices.Equal(a.VPN6, b.VPN6)
}
