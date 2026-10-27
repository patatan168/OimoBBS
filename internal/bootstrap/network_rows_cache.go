// 制御履歴に繰り返される圧縮回線表の、検証済み復号結果を一表だけ保持する。
package bootstrap

import (
	"slices"
	"sync"
)

type networkRowsCache struct {
	mu      sync.Mutex
	encoded string
	rows    networkRows
}

var decodedNetworkRows networkRowsCache

// decode は完全一致する圧縮byteだけを再利用し、呼出元による変更を複製で分離する。
// missは展開上限・完全型・全行の制約を検査し、成功時だけ前の一表を置換する。
func (c *networkRowsCache) decode(encoded string) (networkRows, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rows != nil && c.encoded == encoded {
		return slices.Clone(c.rows), nil
	}
	raw, err := decompressNetworkData(encoded, networkRowsJSONLimit)
	if err != nil {
		return nil, err
	}
	rows, err := decodeNetworkRowArray(raw, true)
	if err != nil {
		return nil, err
	}
	c.encoded, c.rows = encoded, slices.Clone(rows)
	return rows, nil
}
