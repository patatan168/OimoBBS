// 同一公開版のHTML・gzip/zstdを共有し、生成CPUと総保持メモリを有界にする。
package compat

import (
	"bytes"
	"compress/gzip"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"sync"

	"oimobbs/internal/zstdencode"
)

// GzipETagSuffix は小本文level6・大本文の最小gzip選択を識別する。
const GzipETagSuffix = "-gzip-v3"

// ZstdETagSuffix は列ごとにFSE精度を選ぶ圧縮表現を識別する。
const ZstdETagSuffix = "-zstd-v8"

// ErrCompressionCapacity は資源別の生成・待機上限（最大64件）または作業メモリへ達したことを表す。
var ErrCompressionCapacity = errors.New("compression queue full")

type compressionKey struct {
	kind, version string
}

type compressionEntry struct {
	key   compressionKey
	value cachedRepresentation
	cost  uint64
}
type compressionFlight struct {
	done  chan struct{}
	value cachedRepresentation
	err   error
}

// CompressionCache は公開本文の生成と全圧縮方式が保持容量・同時処理枠を共有するLRU。
// 返却byteは変更禁止。送信時の公開権限検査は呼出元が毎回行う。
type CompressionCache struct {
	mu                         sync.Mutex
	limit, used                uint64
	entries                    map[compressionKey]*list.Element
	order                      list.List
	flights                    map[compressionKey]*compressionFlight
	workers                    []*compressionWorker
	workerLimit, activeWorkers int
	workerWake                 chan struct{}
	builds, hits               uint64
	resources                  func() (uint64, int)
	admit                      func() (func(), bool)
}

// NewCompressionCache は最大保持byteと同時生成数の初期値を設定する。容量0なら保持せず処理だけ共有する。
func NewCompressionCache(limit uint64, workers int) *CompressionCache {
	c := &CompressionCache{limit: limit, entries: make(map[compressionKey]*list.Element), flights: make(map[compressionKey]*compressionFlight), workers: make([]*compressionWorker, 0, max(1, workers)), workerLimit: max(1, workers), workerWake: make(chan struct{})}
	return c
}

// Gzip は同じ版の圧縮を一度だけ行う。待機中は要求取消に追従する。
// 本文は処理完了まで不変でなければならない。取消された先行処理のエラーは共有する。
func (c *CompressionCache) Gzip(ctx context.Context, key string, body []byte) ([]byte, error) {
	return c.Compress(ctx, "gzip", key, body)
}

// Compress は方式と表現ETagをキーに、条件評価後の圧縮を同一版で共有する。
// 返却配列は変更禁止。取消された先行要求のエラーは待機者へ共有する。
func (c *CompressionCache) Compress(ctx context.Context, coding, key string, body []byte) ([]byte, error) {
	if coding != "gzip" && coding != "zstd" {
		return nil, errors.New("unsupported compression")
	}
	value, err := c.build(ctx, compressionKey{coding, key}, func(worker *compressionWorker) (cachedRepresentation, error) {
		result, err := worker.compressCoding(coding, body)
		return cachedRepresentation{body: result}, err
	})
	return value.body, err
}

// Render は変更不能な公開版の本文生成を共有する。圧縮と同じ容量・処理枠を使用する。
// keyは生成に影響する全状態を含め、返却配列は変更しない。失効判定は呼出元が毎回行う。
func (c *CompressionCache) Render(ctx context.Context, key string, render func() ([]byte, error)) ([]byte, error) {
	value, err := c.build(ctx, compressionKey{"render", key}, func(*compressionWorker) (cachedRepresentation, error) {
		body, err := render()
		return cachedRepresentation{body: body}, err
	})
	return value.body, err
}

// RenderedFeed は生成済み本文と従来と同じ本文SHA-256の検証子。Bodyは変更禁止。
type RenderedFeed struct {
	Body []byte
	Tag  string
}

type cachedRepresentation struct {
	body []byte
	tag  string
}

// FeedTag は非DAT公開本文の強い検証子の共通部分を返す。
func FeedTag(body []byte) string {
	sum := sha256.Sum256(body)
	return "feed-" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// RenderFeed は本文と検証子を同じ有界エントリで共有し、再検証での全文ハッシュを省く。
// keyは生成に影響する全状態を含める。公開リースと閲覧許可は呼出元が毎回検査する。
func (c *CompressionCache) RenderFeed(ctx context.Context, key string, render func() ([]byte, error)) (RenderedFeed, error) {
	value, err := c.build(ctx, compressionKey{"feed", key}, func(*compressionWorker) (cachedRepresentation, error) {
		body, err := render()
		if err != nil {
			return cachedRepresentation{}, err
		}
		return cachedRepresentation{body: body, tag: FeedTag(body)}, nil
	})
	return RenderedFeed{Body: value.body, Tag: value.tag}, err
}

// build は同じ公開表現の処理を一つにまとめ、待機・保持量を有界にする。
func (c *CompressionCache) build(ctx context.Context, key compressionKey, build func(*compressionWorker) (cachedRepresentation, error)) (cachedRepresentation, error) {
	if err := ctx.Err(); err != nil {
		return cachedRepresentation{}, err
	}
	c.mu.Lock()
	c.refreshLocked()
	if entry := c.entries[key]; entry != nil {
		c.hits++
		c.order.MoveToFront(entry)
		result := entry.Value.(compressionEntry).value
		c.mu.Unlock()
		return result, nil
	}
	if flight := c.flights[key]; flight != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return cachedRepresentation{}, ctx.Err()
		case <-flight.done:
			return flight.value, flight.err
		}
	}
	pendingLimit := 64
	if c.resources != nil {
		// 待機者は生成器を持たず、HTTP側の入力予約を保持する。CPU枠と保持予算に応じて
		// 有界な短いburstを受け、同時生成・8MiB作業予約の上限は増やさない。
		pendingLimit = max(4, min(64, c.workerLimit*4+int(c.limit/(32<<20))))
	}
	if c.workerLimit == 0 || len(c.flights) >= pendingLimit {
		c.mu.Unlock()
		return cachedRepresentation{}, ErrCompressionCapacity
	}
	flight := &compressionFlight{done: make(chan struct{})}
	c.flights[key] = flight
	admit := c.admit
	c.mu.Unlock()
	writer, err := c.acquireWorker(ctx)
	if err != nil {
		flight.err = err
	} else {
		if flight.err = ctx.Err(); flight.err == nil {
			release := func() {}
			accepted := true
			if admit != nil {
				release, accepted = admit()
			}
			if !accepted {
				flight.err = ErrCompressionCapacity
			} else {
				if writer == nil {
					writer = &compressionWorker{}
				}
				flight.value, flight.err = build(writer)
				release()
			}
		}
		c.releaseWorker(writer)
	}
	c.mu.Lock()
	if flight.err == nil {
		c.builds++
		cost := uint64(cap(flight.value.body) + len(key.kind) + 1 + len(key.version) + len(flight.value.tag) + 288)
		if cost <= c.limit {
			for c.used+cost > c.limit {
				old := c.order.Back()
				item := old.Value.(compressionEntry)
				delete(c.entries, item.key)
				c.used -= item.cost
				c.order.Remove(old)
			}
			c.entries[key] = c.order.PushFront(compressionEntry{key, flight.value, cost})
			c.used += cost
		}
	}
	delete(c.flights, key)
	close(flight.done)
	c.mu.Unlock()
	return flight.value, flight.err
}

// compressGzip は共有cacheと同じgzip-v3の規則で圧縮する。
func compressGzip(body []byte) []byte {
	return (&compressionWorker{}).compress(body)
}

// compressionWorker は圧縮器を遅延作成して再利用する。候補処理は同じworker枠内で直列に行う。
type compressionWorker struct {
	writers [3]*gzip.Writer
	zstd    *zstdencode.Encoder
}

// compress は16KiB以上だけlevel1/6/9を比較し、level6以下の長さの本文を返す。
// 同じ長さなら先行候補を採用し、同じ入力の強いETagに同じbyteを対応させる。
func (w *compressionWorker) compress(body []byte) []byte {
	levels := [3]int{6, 1, 9}
	var best []byte
	for slot, level := range levels {
		if slot > 0 && len(body) < 16<<10 {
			break
		}
		if w.writers[slot] == nil {
			w.writers[slot], _ = gzip.NewWriterLevel(io.Discard, level)
		}
		candidate := compressWithWriter(w.writers[slot], body)
		if best == nil || len(candidate) < len(best) {
			best = candidate
		}
	}
	return best
}

// compressWithWriter はworker専用の圧縮器を再利用し、前回の本文参照を残さない。
func compressWithWriter(writer *gzip.Writer, body []byte) []byte {
	var b bytes.Buffer
	writer.Reset(&b)
	_, _ = writer.Write(body)
	_ = writer.Close()
	writer.Reset(io.Discard)
	return b.Bytes()
}

// CompressionCacheStatus は本文や接続元を含まない稼働集計。
type CompressionCacheStatus struct {
	Limit   uint64 `json:"limit_bytes"`
	Used    uint64 `json:"used_bytes"`
	Entries int    `json:"entries"`
	Workers int    `json:"workers"`
	Pending int    `json:"pending_versions"`
	Builds  uint64 `json:"builds"`
	Hits    uint64 `json:"hits"`
}

// Status は公開表現の保持量・生成回数を同じロック内で取得する。
func (c *CompressionCache) Status() CompressionCacheStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CompressionCacheStatus{Limit: c.limit, Used: c.used, Entries: c.order.Len(), Workers: c.workerLimit, Pending: len(c.flights), Builds: c.builds, Hits: c.hits}
}

// compressCoding は圧縮器内の追加並列を止め、共有worker枠だけで実行数を制限する。
func (w *compressionWorker) compressCoding(coding string, body []byte) ([]byte, error) {
	switch coding {
	case "gzip":
		return w.compress(body), nil
	case "zstd":
		if w.zstd == nil {
			w.zstd = &zstdencode.Encoder{}
		}
		return w.zstd.Encode(body), nil
	}

	return nil, errors.New("unsupported compression")
}

// Configure は保持上限と同時生成数を変更する。実行中の生成と送信中の本文は保持する。
func (c *CompressionCache) Configure(limit uint64, workers int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources = nil
	c.configureLocked(limit, max(1, workers))
}

// SetResources は資源の自動計算を登録する。計算は短いロック内で行い、I/Oを含めない。
// workers=0は新規生成を即時拒否する。既存の送信・生成・同じ版の共有待機は完了させる。
func (c *CompressionCache) SetResources(resources func() (uint64, int)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resources = resources
	c.refreshLocked()
}

// SetAdmission は生成開始直前の共有メモリ予約を登録する。拒否なら本文を生成しない。
// releaseは生成完了時に呼び、キャッシュや送信中の本文は利用側の実メモリ観測へ移す。
func (c *CompressionCache) SetAdmission(admit func() (func(), bool)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.admit = admit
}

// RefreshResources は要求がなくても監視側から保持量・新規生成数を縮められる。
func (c *CompressionCache) RefreshResources() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshLocked()
}

func (c *CompressionCache) refreshLocked() {
	if c.resources != nil {
		limit, workers := c.resources()
		c.configureLocked(limit, max(0, workers))
	}
}

func (c *CompressionCache) configureLocked(limit uint64, workers int) {
	if c.limit == limit && c.workerLimit == workers {
		return
	}
	previousEntries := c.order.Len()
	c.limit = limit
	c.workerLimit = workers
	keep := max(0, c.workerLimit-c.activeWorkers)
	if len(c.workers) > keep {
		clear(c.workers[keep:])
		c.workers = c.workers[:keep]
	}
	for c.used > limit {
		old := c.order.Back()
		item := old.Value.(compressionEntry)
		delete(c.entries, item.key)
		c.used -= item.cost
		c.order.Remove(old)
	}
	if previousEntries > c.order.Len()*2+64 {
		entries := make(map[compressionKey]*list.Element, c.order.Len())
		for entry := c.order.Front(); entry != nil; entry = entry.Next() {
			entries[entry.Value.(compressionEntry).key] = entry
		}
		c.entries = entries
	}
	close(c.workerWake)
	c.workerWake = make(chan struct{})
}

// acquireWorker は現在の上限まで実行を許可し、上限変更と要求取消で待機を解除する。
func (c *CompressionCache) acquireWorker(ctx context.Context) (*compressionWorker, error) {
	for {
		c.mu.Lock()
		if err := ctx.Err(); err != nil {
			c.mu.Unlock()
			return nil, err
		}
		if c.workerLimit == 0 {
			c.mu.Unlock()
			return nil, ErrCompressionCapacity
		}
		if c.activeWorkers < c.workerLimit {
			c.activeWorkers++
			var worker *compressionWorker
			if n := len(c.workers); n > 0 {
				worker = c.workers[n-1]
				c.workers[n-1] = nil
				c.workers = c.workers[:n-1]
			}
			c.mu.Unlock()
			return worker, nil
		}
		wake := c.workerWake
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wake:
		}
	}
}

// releaseWorker は生成器を再利用し、上限減少で余った生成器は保持しない。
func (c *CompressionCache) releaseWorker(worker *compressionWorker) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.activeWorkers--
	if len(c.workers)+c.activeWorkers < c.workerLimit {
		c.workers = append(c.workers, worker)
	}
	close(c.workerWake)
	c.workerWake = make(chan struct{})
}
