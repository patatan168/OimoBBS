// 投稿ごとに更新される公開HTMLでは、gzipの探索回数を減らしてCPU処理を有界にする。
package compat

import (
	"compress/gzip"
	"context"
	"io"
)

// GzipLiveETagSuffix は更新中HTML用のlevel1表現を通常の強い検証子から分離する。
const GzipLiveETagSuffix = "-gzip-live-v1"

// CompressLive は更新中HTMLのgzipを一回のlevel1圧縮で作る。返却配列は変更禁止。
// cache容量・処理枠・取消は通常経路と共有し、zstdには通常と同じ表現を返す。
func (c *CompressionCache) CompressLive(ctx context.Context, coding, key string, body []byte) ([]byte, error) {
	if coding != "gzip" {
		return c.Compress(ctx, coding, key, body)
	}
	value, err := c.build(ctx, compressionKey{"gzip-live-v1", key}, func(w *compressionWorker) (cachedRepresentation, error) {
		if w.writers[1] == nil {
			w.writers[1], _ = gzip.NewWriterLevel(io.Discard, gzip.BestSpeed)
		}
		return cachedRepresentation{body: compressWithWriter(w.writers[1], body)}, nil
	})
	return value.body, err
}
