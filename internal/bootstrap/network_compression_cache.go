// 同じ表の再圧縮を省き、Zstandardの再実行と割当てを減らす。
package bootstrap

import (
	"bytes"
	"sync"
)

type networkCompressionEntry struct {
	raw     []byte
	encoded string
}
type networkCompressionCache struct {
	mu      sync.Mutex
	entries [2]networkCompressionEntry
}

var networkPrefixCompression networkCompressionCache
var networkConfigCompression networkCompressionCache
var networkRowCompression networkCompressionCache
var networkCountryCompression networkCompressionCache

// compress は完全一致するbyteだけを再利用する。入力は複製して最大二版に制限する。
// 検証結果を省略するcacheではなく、同じZstandard符号化だけを共有する。
func (c *networkCompressionCache) compress(raw []byte) (string, error) {
	if len(raw) > networkRowsJSONLimit {
		return compressNetworkData(raw)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, entry := range c.entries {
		if entry.encoded != "" && bytes.Equal(raw, entry.raw) {
			if i == 1 {
				c.entries[0], c.entries[1] = c.entries[1], c.entries[0]
			}
			return entry.encoded, nil
		}
	}
	encoded, err := compressNetworkData(raw)
	if err != nil {
		return "", err
	}
	c.entries[1], c.entries[0] = c.entries[0], networkCompressionEntry{bytes.Clone(raw), encoded}
	return encoded, nil
}
