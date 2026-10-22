// 同一の隔離ダミーDATで圧縮の送信量・CPU時間・確保量を比較する。ネットワークには接続しない。
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"

	"oimobbs/internal/compat"
	"oimobbs/internal/testutil"
)

type measurement struct {
	Name             string `json:"name"`
	Coding           string `json:"coding"`
	InputBytes       int    `json:"input_bytes"`
	EncodedBytes     int    `json:"encoded_bytes"`
	NanosecondsPerOp int64  `json:"nanoseconds_per_op"`
	BytesPerOp       uint64 `json:"allocated_bytes_per_op"`
	AllocsPerOp      uint64 `json:"allocs_per_op"`
}

// measure はworkerの初期確保・復号を計測外へ置き、版を変えて共有cacheへの命中を避ける。
func measure(name, coding string, body []byte, n int) measurement {
	cache := compat.NewCompressionCache(0, 1)
	encoded, err := cache.Compress(context.Background(), coding, "warm", body)
	must(err)
	var decoded []byte
	if coding == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(encoded))
		must(err)
		decoded, err = io.ReadAll(reader)
		must(err)
		must(reader.Close())
	} else {
		decoded, err = testutil.DecodeZstd(encoded)
		must(err)
	}
	if !bytes.Equal(decoded, body) {
		panic("roundtrip mismatch")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	for i := range n {
		result, err := cache.Compress(context.Background(), coding, strconv.Itoa(i), body)
		must(err)
		if len(result) != len(encoded) {
			panic("nondeterministic size")
		}
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	return measurement{name, coding, len(body), len(encoded), int64(elapsed) / int64(n), (after.TotalAlloc - before.TotalAlloc) / uint64(n), (after.Mallocs - before.Mallocs) / uint64(n)}
}

func main() {
	dat := flag.String("dat", "", "1MiB以下の隔離ダミーDAT")
	output := flag.String("output", "", "新規JSON出力先")
	count := flag.Int("count", 100, "各条件の圧縮回数")
	flag.Parse()
	if *dat == "" || *output == "" || *count < 1 || *count > 10000 {
		panic("invalid arguments")
	}
	file, err := os.Open(*dat)
	must(err)
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	must(err)
	must(file.Close())
	if len(raw) == 0 || len(raw) > 1<<20 {
		panic("invalid DAT size")
	}
	var rows []measurement
	for _, sample := range []struct {
		name string
		body []byte
	}{{"actual-1000", raw}, {"small-one-line", bytes.Split(raw, []byte{'\n'})[0]}, {"text-1000", testutil.DATFixture("text")}, {"mixed-1000", testutil.DATFixture("mixed")}} {
		for _, coding := range []string{"gzip", "zstd"} {
			for range 3 {
				rows = append(rows, measure(sample.name, coding, sample.body, *count))
			}
		}
	}
	result, err := json.MarshalIndent(rows, "", "  ")
	must(err)
	saved, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	must(err)
	_, err = saved.Write(result)
	must(err)
	must(saved.Close())
}

// must は計測・復号・出力の失敗を成功結果に混ぜない。
func must(err error) {
	if err != nil {
		panic(err)
	}
}
