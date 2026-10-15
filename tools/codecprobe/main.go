// codecprobe は隔離Linux環境で固定DATのGo圧縮時間・作業メモリを比較する。
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"oimobbs/internal/delivery"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"oimobbs/internal/compat"
	"oimobbs/internal/platform"
	"oimobbs/internal/testutil"
	"oimobbs/internal/zstdencode"
)

// encoder は一処理内で再利用し、製品と同じ低メモリ候補を比較する。
func encoder(codec string) (func([]byte) []byte, func([]byte) []byte) {
	switch codec {
	case "gzip":
		cache := compat.NewCompressionCache(0, 1)
		revision := 0
		return func(raw []byte) []byte {
				revision++
				b, e := cache.Gzip(context.Background(), fmt.Sprint(revision), raw)
				if e != nil {
					panic(e)
				}
				return b
			}, func(b []byte) []byte {
				r, e := gzip.NewReader(bytes.NewReader(b))
				if e != nil {
					panic(e)
				}
				defer r.Close()
				v, e := io.ReadAll(r)
				if e != nil {
					panic(e)
				}
				return v
			}
	case "zstd-own":
		w := &zstdencode.Encoder{}
		return w.Encode, func(b []byte) []byte {
			raw, e := testutil.DecodeZstd(b)
			if e != nil {
				panic(e)
			}
			return raw
		}

	}
	panic("unknown codec")
}

// counters はコンテナ自身のcgroup CPU集計を読み、ホスト全体と混同しない。
func counters() map[string]uint64 {
	b, _ := os.ReadFile("/sys/fs/cgroup/cpu.stat")
	v := map[string]uint64{}
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 {
			v[parts[0]], _ = strconv.ParseUint(parts[1], 10, 64)
		}
	}
	return v
}

func main() {
	codec := flag.String("codec", "gzip", "gzip/zstd-own")
	corpus := flag.String("corpus", "entropy", "entropy/text/mixed")
	seconds := flag.Int("seconds", 5, "更新測定秒数")
	listen := flag.String("listen", "", "loopback HTTPS比較サーバー")
	cert := flag.String("cert", "", "検証証明書")
	key := flag.String("key", "", "検証鍵")
	updates := flag.Int("updates", 0, "毎秒の合成改版数")
	flag.Parse()
	platform.ConfigureRuntime()
	raw := testutil.DATFixture(*corpus)
	if *listen != "" {
		serve(*listen, *cert, *key, *updates, raw)
		return
	}
	encode, decode := encoder(*codec)
	compressed := encode(raw)
	if !bytes.Equal(decode(compressed), raw) {
		panic("roundtrip mismatch")
	}
	before := counters()
	started := time.Now()
	times := []float64{}
	for i := range *seconds * 20 {
		target := started.Add(time.Duration(i) * 50 * time.Millisecond)
		if d := time.Until(target); d > 0 {
			time.Sleep(d)
		}
		// byte数を維持しつつ版を変更し、同一本文のcache測定にしない。
		revision := bytes.Clone(raw)
		copy(revision, fmt.Sprintf("%08d", i))
		t := time.Now()
		compressed = encode(revision)
		times = append(times, float64(time.Since(t))/1e6)
	}
	elapsed := time.Since(started).Seconds()
	after := counters()
	last := bytes.Clone(raw)
	copy(last, fmt.Sprintf("%08d", *seconds*20-1))
	if !bytes.Equal(decode(compressed), last) {
		panic("updated roundtrip mismatch")
	}
	sort.Float64s(times)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	peak, _ := os.ReadFile("/sys/fs/cgroup/memory.peak")
	oom, _ := os.ReadFile("/sys/fs/cgroup/memory.events")
	result := map[string]any{"scope": "encoding only; first and last versions independently decoded outside measured CPU interval", "codec": *codec, "corpus": *corpus, "raw_bytes": len(raw), "encoded_bytes": len(compressed), "updates": len(times), "seconds": elapsed, "updates_per_second": float64(len(times)) / elapsed, "compression_p50_ms": times[len(times)/2], "compression_p95_ms": times[len(times)*95/100], "cpu_cores": float64(after["usage_usec"]-before["usage_usec"]) / 1e6 / elapsed, "throttled_usec": after["throttled_usec"] - before["throttled_usec"], "go_heap_inuse": mem.HeapInuse, "go_sys_bytes": mem.Sys, "memory_peak_bytes": strings.TrimSpace(string(peak)), "memory_events": string(oom)}
	if e := json.NewEncoder(os.Stdout).Encode(result); e != nil {
		panic(e)
	}
}

// serve は製品の表現選択・共有cache・80Mbps送信器を通す合成版交換試験。
// 公開保存や投稿処理は含まず、外部originへ接続しない。
func serve(listen, cert, key string, updates int, raw []byte) {
	if !strings.HasPrefix(listen, "127.0.0.1:") || updates < 0 || updates > 100 {
		panic("loopback and bounded updates required")
	}
	cache := compat.NewCompressionCache(16<<20, min(8, runtime.GOMAXPROCS(0)))
	scheduler, err := delivery.New(80_000_000)
	if err != nil {
		panic(err)
	}
	defer scheduler.Close()
	var mu sync.Mutex
	started := time.Now()
	revision := int64(-1)
	var body []byte
	tag := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/status" {
			_ = json.NewEncoder(w).Encode(cache.Status())
			return
		}
		mu.Lock()
		next := int64(0)
		if updates > 0 {
			next = time.Since(started).Nanoseconds() / (int64(time.Second) / int64(updates))
		}
		if revision != next {
			body = bytes.Clone(raw)
			copy(body, fmt.Sprintf("%08d", next))
			tag = fmt.Sprintf("%x", sha256.Sum256(body))
			revision = next
		}
		p := compat.Representation{DAT: body, DisableRange: true, Compress: cache.Compress, ETagIdentity: `"` + tag + `-identity"`, ETagGzip: `"` + tag + compat.GzipETagSuffix + `"`, ETagZstd: `"` + tag + compat.ZstdETagSuffix + `"`}
		w.Header().Set("X-Body-SHA256", tag)
		mu.Unlock()
		compat.ServeDAT(w, r, p)
	})
	server := &http.Server{Addr: listen, Handler: scheduler.Wrap(handler), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second}
	if err := server.ListenAndServeTLS(cert, key); err != nil {
		panic(err)
	}
}
