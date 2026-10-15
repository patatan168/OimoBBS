// 隔離loopback HTTPSで、実況差分・更新なし・全文集中の配信部品を測定する。
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"oimobbs/internal/compat"
	"oimobbs/internal/delivery"
)

type version struct {
	body     []byte
	revision int
}
type outcome struct {
	status  int
	size    int
	latency time.Duration
	err     error
}
type phase struct {
	Name            string      `json:"name"`
	Requests        int         `json:"requests"`
	Errors          int         `json:"errors"`
	Status          map[int]int `json:"status"`
	BodyBytes       int         `json:"body_bytes"`
	P95MS           float64     `json:"p95_ms"`
	DurationSeconds float64     `json:"duration_seconds"`
}

// main は外部URLを受理せず、200個の実loopback送信元・1000読者だけを生成する。
// 投稿Sync・保存・公開権限は測らず、配信層の基準負荷と集中取得を分離する。
func main() {
	runtime.GOMAXPROCS(2)
	scheduler, err := delivery.New(80_000_000)
	must(err)
	defer scheduler.Close()
	gate, err := delivery.NewRequestGate(2048, 32)
	must(err)
	cache := compat.NewCompressionCache(16<<20, 2)
	var current atomic.Pointer[version]
	original := make([]byte, 0, 250000)
	for i := range 1000 {
		original = append(original, row(i)...)
	}
	current.Store(&version{original, 1})
	server := httptest.NewUnstartedServer(scheduler.Wrap(gate.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := current.Load()
		tag := fmt.Sprintf("probe-%d", v.revision)
		compat.ServeDAT(w, r, compat.Representation{DAT: v.body, ETagIdentity: `"` + tag + `-identity"`, ETagGzip: `"` + tag + `-gzip-v1"`, Compress: cache.Compress})
	}))))
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	clients := make([]*http.Client, 200)
	for i := range clients {
		dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(fmt.Sprintf("127.1.%d.%d", i/250, i%250+1))}, Timeout: 5 * time.Second}
		transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableCompression: true, MaxIdleConns: 10, MaxIdleConnsPerHost: 5, MaxConnsPerHost: 5}
		clients[i] = &http.Client{Transport: transport, Timeout: 5 * time.Second}
		defer transport.CloseIdleConnections()
	}
	phases := []phase{}
	offsets := make([]int, 1000)
	// 初回を5秒へ分散し、warmupの拒否/本文量も記録する。
	phases = append(phases, run("initial_gzip", 1000, 5*time.Millisecond, func(i int) outcome {
		result, body := fetch(clients[i%200], server.URL, "gzip", "")
		if result.err == nil && result.status == 200 {
			reader, e := gzip.NewReader(bytes.NewReader(body))
			if e == nil {
				var raw []byte
				raw, e = io.ReadAll(reader)
				reader.Close()
				if e == nil && !bytes.Equal(raw, original) {
					e = fmt.Errorf("initial mismatch")
				}
				offsets[i] = len(raw)
			}
			result.err = e
		}
		return result
	}))
	// 20件/秒×250byteの合成確定版を交換する。これは投稿処理の測定ではない。
	stop := make(chan struct{})
	updated := make(chan struct{})
	go func() {
		defer close(updated)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				old := current.Load()
				body := append(bytes.Clone(old.body), row(old.revision+1000)...)
				current.Store(&version{body, old.revision + 1})
			}
		}
	}()
	phases = append(phases, run("live_range_1000_per_second", 10000, time.Millisecond, func(i int) outcome {
		reader := i % 1000
		offset := max(0, offsets[reader]-1)
		result, body := fetch(clients[reader%200], server.URL, "identity", fmt.Sprintf("bytes=%d-", offset))
		if result.err == nil && result.status == 206 {
			offsets[reader] = offset + len(body)
			if len(body) == 0 || body[len(body)-1] != '\n' {
				result.err = fmt.Errorf("incomplete DAT")
			}
		}
		return result
	}))
	close(stop)
	<-updated
	tag := fmt.Sprintf(`"probe-%d-identity"`, current.Load().revision)
	phases = append(phases, run("unchanged_304_1000_per_second", 3000, time.Millisecond, func(i int) outcome { return conditional(clients[i%200], server.URL, tag) }))
	phases = append(phases, run("full_gzip_burst_1000", 1000, 100*time.Microsecond, func(i int) outcome { result, _ := fetch(clients[i%200], server.URL, "gzip", ""); return result }))
	phases = append(phases, run("recovery_range_1000_per_second", 3000, time.Millisecond, func(i int) outcome {
		reader := i % 1000
		offset := max(0, offsets[reader]-1)
		result, body := fetch(clients[reader%200], server.URL, "identity", fmt.Sprintf("bytes=%d-", offset))
		if result.status == 206 && result.err == nil {
			expected := current.Load().body[offset:]
			if !bytes.Equal(body, expected) {
				result.err = fmt.Errorf("recovery mismatch")
			}
			offsets[reader] = offset + len(body)
		}
		return result
	}))
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	result := map[string]any{"scope": "synthetic delivery only; no posting WAL, repository listing, NIC or remote RTT", "readers": 1000, "source_ips": 200, "gomaxprocs": runtime.GOMAXPROCS(0), "go": runtime.Version(), "initial_dat_bytes": len(original), "final_dat_bytes": len(current.Load().body), "phases": phases, "compression": cache.Status(), "delivery": scheduler.Status(), "heap_bytes": memory.HeapAlloc, "goroutines": runtime.NumGoroutine()}
	for _, name := range []string{"memory.peak", "memory.max", "cpu.max", "cpu.stat"} {
		value, err := os.ReadFile("/sys/fs/cgroup/" + name)
		if err == nil {
			result[name] = strings.TrimSpace(string(value))
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(result))
	for i, p := range phases {
		if i == 3 {
			continue
		}
		expected := []int{200, 206, 304, 0, 206}[i]
		if p.Errors != 0 || p.Status[expected] != p.Requests {
			os.Exit(1)
		}
	}
}

// row は一意番号と文章を含む250byteの合成DAT行を作る。
func row(i int) []byte {
	text := fmt.Sprintf("name<>sage<>2026 ID:%08x<>実況 response %d >>%d https://example.invalid/%d 本文確認 <>title", i, i, max(1, i-1), i)
	return []byte(text + strings.Repeat(".", 249-len(text)) + "\n")
}

// fetch は圧縮本文のbyteをそのまま数え、Range時は返却範囲を照合する。
func fetch(client *http.Client, target, encoding, byteRange string) (outcome, []byte) {
	r, err := http.NewRequest("GET", target, nil)
	must(err)
	r.Header.Set("Accept-Encoding", encoding)
	if byteRange != "" {
		r.Header.Set("Range", byteRange)
	}
	start := time.Now()
	response, err := client.Do(r)
	if err != nil {
		return outcome{latency: time.Since(start), err: err}, nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if response.StatusCode == 206 {
		var begin, end, total int
		_, e := fmt.Sscanf(response.Header.Get("Content-Range"), "bytes %d-%d/%d", &begin, &end, &total)
		expected, _ := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(byteRange, "bytes="), "-"))
		if e != nil || begin != expected || end+1 != total || len(body) != end-begin+1 {
			err = fmt.Errorf("bad range")
		}
	}
	return outcome{status: response.StatusCode, size: len(body), latency: time.Since(start), err: err}, body
}

// conditional は本文を省略した304応答を照合する。
func conditional(client *http.Client, target, tag string) outcome {
	r, err := http.NewRequest("GET", target, nil)
	must(err)
	r.Header.Set("If-None-Match", tag)
	r.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	response, err := client.Do(r)
	if err != nil {
		return outcome{latency: time.Since(start), err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if response.StatusCode != 304 || len(body) != 0 {
		err = fmt.Errorf("conditional mismatch")
	}
	return outcome{status: response.StatusCode, size: len(body), latency: time.Since(start), err: err}
}

// run は予定時刻を保持し、同じ読者の前回待ちを未発行エラーとして数える。
func run(name string, count int, interval time.Duration, request func(int) outcome) phase {
	start := time.Now()
	results := make(chan outcome, count)
	var wg sync.WaitGroup
	busy := make([]atomic.Bool, 1000)
	for i := range count {
		timer := time.NewTimer(max(0, time.Until(start.Add(time.Duration(i)*interval))))
		<-timer.C
		if !busy[i%1000].CompareAndSwap(false, true) {
			results <- outcome{err: fmt.Errorf("reader still waiting")}
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer busy[i%1000].Store(false); results <- request(i) }()
	}
	wg.Wait()
	close(results)
	p := phase{Name: name, Requests: count, Status: make(map[int]int), DurationSeconds: time.Since(start).Seconds()}
	latencies := make([]time.Duration, 0, count)
	for result := range results {
		p.Status[result.status]++
		p.BodyBytes += result.size
		latencies = append(latencies, result.latency)
		if result.err != nil {
			p.Errors++
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p.P95MS = float64(latencies[(len(latencies)*95+99)/100-1]) / float64(time.Millisecond)
	return p
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
