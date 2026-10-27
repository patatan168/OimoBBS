//go:build linux

// 隔離データの実HTTPでWAF OFF/検査のみ/検査と頻度制限を比較する任意実行の性能試験。
package bootstrap

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestWAFPublicReadPerformance はネットワーク・通常ルーティング・応答生成を含める。
// 同一プロセスのloopback測定で、本番やWANの最大処理件数は保証しない。
func TestWAFPublicReadPerformance(t *testing.T) {
	if os.Getenv("OIMO_WAF_PERFORMANCE") != "1" {
		t.Skip("set OIMO_WAF_PERFORMANCE=1 for isolated HTTP measurement")
	}
	_, repo := adminFixture(t)
	defer repo.Close()
	useHealthyPostingCapacity(t, repo)
	board, err := repo.CreateBoard(t.Context(), "news", "性能試験")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	posted, err := sendForm(form, url.Values{"bbs": {"news"}, "subject": {"WAFの合成テスト"}, "MESSAGE": {"通常の日本語の本文です。外部の個人情報は含みません。"}, "oimo_request_id": {"waf-performance-0001"}})
	form.Close()
	if err != nil || !posted.Accepted {
		t.Fatal(posted, err)
	}
	server := wafPublicServer(t, repo)
	tr := &http.Transport{MaxIdleConns: 16, MaxIdleConnsPerHost: 16, DisableCompression: true}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	dat := fmt.Sprintf("/news/dat/%d.dat", posted.Key)
	req, _ := http.NewRequest("GET", server.URL+dat, nil)
	req.Host = "127.0.0.1:9080"
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	etag := response.Header.Get("ETag")
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if etag == "" {
		t.Fatal("missing fixture etag")
	}
	type sample struct {
		path, method, header, value string
		status                      int
	}
	samples := []sample{{dat, "GET", "", "", 200}, {"/news/subject.txt", "GET", "", "", 200}, {dat, "GET", "If-None-Match", etag, 304}, {dat, "GET", "Range", "bytes=5-", 206}, {dat, "HEAD", "", "", 200}, {"/news/", "GET", "", "", 200}}
	workersCount := 8
	if raw := os.Getenv("OIMO_WAF_PERF_WORKERS"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 32 {
			t.Fatal("OIMO_WAF_PERF_WORKERS must be 1..32")
		}
		workersCount = n
	}
	const count = 8192
	for round := range 3 {
		modes := []string{"off", "inspection", "inspection_and_traffic"}
		if round%2 != 0 {
			modes = []string{"inspection_and_traffic", "inspection", "off"}
		}
		for _, mode := range modes {
			policy := repo.wafSettings()
			policy.Enabled = mode != "off"
			policy.Traffic.Enabled = mode == "inspection_and_traffic"
			// 実測では拒否率ではなく検査費用を比較するため、瞬間枠を緩める。
			policy.Traffic.ClientRate = 10000
			policy.Traffic.ClientBurst = 100000
			policy.Traffic.GlobalRate = 100000
			policy.Traffic.GlobalBurst = 200000
			repo.publishWAF(policy)
			// 各条件で全表現を先に読み、初回キャッシュ生成を計測区間から外す。
			for n := range len(samples) * 4 {
				item := samples[n%len(samples)]
				req, _ := http.NewRequest(item.method, server.URL+item.path, nil)
				req.Host = "127.0.0.1:9080"
				if item.header != "" {
					req.Header.Set(item.header, item.value)
				}
				res, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(io.Discard, res.Body)
				res.Body.Close()
				if readErr != nil || res.StatusCode != item.status {
					t.Fatal("warmup response", res.StatusCode, readErr)
				}
			}
			var index, failures, transferred atomic.Int64
			durations := make([]time.Duration, count)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			var cpuBefore, cpuAfter syscall.Rusage
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuBefore); err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			var workers sync.WaitGroup
			for range workersCount {
				workers.Go(func() {
					for {
						n := int(index.Add(1) - 1)
						if n >= count {
							return
						}
						item := samples[n%len(samples)]
						req, _ := http.NewRequest(item.method, server.URL+item.path, nil)
						req.Host = "127.0.0.1:9080"
						req.Header.Set("User-Agent", "Monazilla/1.00 WAFPerformance/1.0")
						if item.header != "" {
							req.Header.Set(item.header, item.value)
						}
						at := time.Now()
						res, err := client.Do(req)
						if err != nil {
							failures.Add(1)
						} else {
							bytes, readErr := io.Copy(io.Discard, res.Body)
							transferred.Add(bytes)
							res.Body.Close()
							if res.StatusCode != item.status || readErr != nil {
								failures.Add(1)
							}
						}
						durations[n] = time.Since(at)
					}
				})
			}
			workers.Wait()
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			if err := syscall.Getrusage(syscall.RUSAGE_SELF, &cpuAfter); err != nil {
				t.Fatal(err)
			}
			cpuTime := time.Duration(cpuAfter.Utime.Nano() + cpuAfter.Stime.Nano() - cpuBefore.Utime.Nano() - cpuBefore.Stime.Nano())
			sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
			t.Logf("round=%d mode=%s completed=%d errors=%d rps=%.1f p95=%s alloc_bytes_per_request=%d cpu_cores=%.2f body_mbps=%.2f", round+1, mode, count, failures.Load(), float64(count)/elapsed.Seconds(), durations[count*95/100], (after.TotalAlloc-before.TotalAlloc)/count, cpuTime.Seconds()/elapsed.Seconds(), float64(transferred.Load()*8)/elapsed.Seconds()/1e6)
			if failures.Load() != 0 {
				t.Fatal("HTTP responses differed from expected status")
			}
		}
	}
}
