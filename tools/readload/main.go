// readload は隔離loopback TLSの固定表現を複数コアで取得し、全応答の内容を照合する。
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type config struct {
	URL             string            `json:"url"`
	Certificate     string            `json:"certificate"`
	Headers         map[string]string `json:"headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	Status          int               `json:"status"`
	SHA256          string            `json:"body_sha256"`
	BodyBytes       int               `json:"body_bytes"`
	Requests        int               `json:"requests"`
	Workers         int               `json:"workers"`
	Rate            int               `json:"rate"`
}

type outcome struct {
	duration       time.Duration
	scheduled, lag time.Duration
	status, bytes  int
	valid          bool
}
type report struct {
	Requests     int         `json:"requests"`
	Errors       int         `json:"errors"`
	Status       map[int]int `json:"status"`
	BodyBytes    int64       `json:"body_bytes"`
	Seconds      float64     `json:"seconds"`
	RPS          float64     `json:"requests_per_second"`
	P50          float64     `json:"p50_ms"`
	P95          float64     `json:"p95_ms"`
	Max          float64     `json:"max_ms"`
	CPU          float64     `json:"client_cpu_seconds"`
	CPUs         int         `json:"client_gomaxprocs"`
	ScheduledP95 float64     `json:"scheduled_p95_ms"`
	MaxLag       float64     `json:"generator_max_lag_ms"`
}

func main() {
	path := flag.String("config", "", "隔離対象と期待応答のJSON")
	cpus := flag.Int("cpus", 2, "負荷生成側のCPU並列数")
	flag.Parse()
	runtime.GOMAXPROCS(*cpus)
	raw, err := os.ReadFile(*path)
	var c config
	if err == nil {
		err = json.Unmarshal(raw, &c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result, err := run(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(result); err != nil || result.Errors > 0 {
		os.Exit(1)
	}
}

// run は明示したCAを信頼する実HTTPSを使い、失敗も含め全予定要求を試行する。
// 接続はworkerごとに再利用し、本文・状態・検証子を照合する。外部ホストは受け付けない。
func run(c config) (report, error) {
	u, err := url.Parse(c.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || c.Requests < 1 || c.Requests > 1000000 || c.Rate < 0 || c.Rate > 100000 || c.Workers < 1 || c.Workers > 256 || c.BodyBytes < 0 || c.BodyBytes > 16<<20 {
		return report{}, fmt.Errorf("invalid isolated load configuration")
	}
	digest, err := hex.DecodeString(c.SHA256)
	if err != nil || len(digest) != sha256.Size {
		return report{}, fmt.Errorf("invalid expected digest")
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(c.Certificate)
	if err != nil {
		return report{}, err
	}
	if !roots.AppendCertsFromPEM(pem) {
		return report{}, fmt.Errorf("invalid CA")
	}
	results := make([]outcome, c.Requests)
	var next atomic.Int64
	var group sync.WaitGroup
	before := cpuSeconds()
	start := time.Now()
	for worker := range min(c.Workers, c.Requests) {
		group.Go(func() { loadWorker(c, roots, worker, &next, results, start) })
	}
	group.Wait()
	out := report{Requests: c.Requests, Status: map[int]int{}, Seconds: time.Since(start).Seconds(), CPU: cpuSeconds() - before, CPUs: runtime.GOMAXPROCS(0)}
	durations := make([]time.Duration, len(results))
	scheduled := make([]time.Duration, len(results))
	var maxLag time.Duration
	for i, result := range results {
		if !result.valid {
			out.Errors++
		}
		out.Status[result.status]++
		out.BodyBytes += int64(result.bytes)
		durations[i] = result.duration
		scheduled[i] = result.scheduled
		maxLag = max(maxLag, result.lag)
	}
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
	sort.Slice(scheduled, func(i, j int) bool { return scheduled[i] < scheduled[j] })
	out.ScheduledP95 = float64(scheduled[min(len(scheduled)-1, len(scheduled)*95/100)]) / 1e6
	out.MaxLag = float64(maxLag) / 1e6
	out.P50 = float64(durations[len(durations)/2]) / 1e6
	out.P95 = float64(durations[min(len(durations)-1, len(durations)*95/100)]) / 1e6
	out.Max = float64(durations[len(durations)-1]) / 1e6
	out.RPS = float64(c.Requests) / out.Seconds
	return out, nil
}

// loadWorker は独立接続を持ち、予定時刻と実HTTP時間を分けて記録する。
func loadWorker(c config, roots *x509.CertPool, worker int, next *atomic.Int64, results []outcome, start time.Time) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 2, byte(worker/250), byte(worker%250+1))}}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableCompression: true, MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for {
		index := int(next.Add(1) - 1)
		if index >= c.Requests {
			return
		}
		var target time.Time
		if c.Rate > 0 {
			target = start.Add(time.Duration(index) * time.Second / time.Duration(c.Rate))
			time.Sleep(time.Until(target))
		}
		begun := time.Now()
		result := fetch(client, c)
		result.duration = time.Since(begun)
		result.scheduled = result.duration
		if c.Rate > 0 {
			result.scheduled = time.Since(target)
			result.lag = max(0, begun.Sub(target))
		}
		results[index] = result
	}
}

// fetch は一要求だけ試行し、短い本文・過大本文・検証子の変化も失敗へ数える。
func fetch(client *http.Client, c config) outcome {
	result := outcome{}
	req, err := http.NewRequest("GET", c.URL, nil)
	if err != nil {
		return result
	}
	for name, value := range c.Headers {
		req.Header.Set(name, value)
	}
	response, err := client.Do(req)
	if err != nil {
		return result
	}
	result.status = response.StatusCode
	body, readErr := io.ReadAll(io.LimitReader(response.Body, int64(c.BodyBytes)+1))
	closeErr := response.Body.Close()
	result.bytes = len(body)
	sum := sha256.Sum256(body)
	result.valid = readErr == nil && closeErr == nil && len(body) == c.BodyBytes && response.StatusCode == c.Status && hex.EncodeToString(sum[:]) == c.SHA256
	for name, value := range c.ResponseHeaders {
		result.valid = result.valid && response.Header.Get(name) == value
	}
	return result
}

// cpuSeconds は負荷生成プロセス自身の全スレッドのuser+system CPU時間を返す。
func cpuSeconds() float64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(err)
	}
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
}
