// 回線設定の完全一致した保存byteだけを共有し、履歴の前後で繰り返す復号・検査を減らす。
package bootstrap

import (
	"encoding/json"
	"sync"

	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

type networkValidationEntry struct {
	raw   string
	state networkState
}

type networkValidationCache struct {
	mu      sync.Mutex
	entries [2]networkValidationEntry
}

var validatedNetworkValues networkValidationCache

// decode は完全型・容量・全行の検査に成功した二版だけを保持する。
// 返すsliceとpointerは変更禁止。状態遷移の比較にだけ用い、管理・更新用の値へ渡さない。
func (c *networkValidationCache) decode(raw json.RawMessage) (networkState, error) {
	if len(raw) > store.MaxNetworkValueJSON {
		return networkState{}, store.ErrCorrupt
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, entry := range c.entries {
		if entry.raw != "" && entry.raw == string(raw) {
			if i == 1 {
				c.entries[0], c.entries[1] = c.entries[1], c.entries[0]
			}
			return entry.state, nil
		}
	}
	var value networkState
	if strictjson.DecodeLimit(raw, &value, store.MaxNetworkValueJSON) != nil || value.validate() != nil {
		return networkState{}, store.ErrCorrupt
	}
	c.entries[1], c.entries[0] = c.entries[0], networkValidationEntry{raw: string(raw), state: value}
	return value, nil
}
