// 別プロセスの製品HTTP/2閲覧経路で国制限の負荷・CPU・socket転送量を測る。明示環境変数時だけ実行する。
package bootstrap

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
)

type countryLoadStats struct {
	CPU float64 `json:"cpu_seconds"`
	RX  int64   `json:"socket_rx_bytes"`
	TX  int64   `json:"socket_tx_bytes"`
}

type countryLoadListener struct {
	net.Listener
	rx, tx atomic.Int64
}

// Accept はTLSより下の実socketへbyte計数を挿入する。
func (l *countryLoadListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countryLoadConn{Conn: c, owner: l}, nil
}

type countryLoadConn struct {
	net.Conn
	owner *countryLoadListener
}

// Read は実socketから受信したbyteだけを計数する。
func (c *countryLoadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.owner.rx.Add(int64(n))
	return n, err
}

// Write は実socketへ送信できたbyteだけを計数する。
func (c *countryLoadConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.owner.tx.Add(int64(n))
	return n, err
}

// countryLoadCPU はこのプロセスだけの全スレッドのuser+system CPU秒を返す。
func countryLoadCPU() float64 {
	var r syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &r); err != nil {
		panic(err)
	}
	return float64(r.Utime.Sec+r.Stime.Sec) + float64(r.Utime.Usec+r.Stime.Usec)/1e6
}

// TestCountryPermissionLoadServer は親試験専用のloopback TLSサーバーを作り、stdin閉鎖で終了する。
func TestCountryPermissionLoadServer(t *testing.T) {
	if os.Getenv("OIMO_COUNTRY_LOAD_CHILD") != "1" {
		t.Skip("isolated load subprocess only")
	}
	runtime.GOMAXPROCS(2)
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "国判定の隔離測定"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "loadtest", "測定用の板")
	if err != nil {
		t.Fatal(err)
	}
	repo.liveNetworks.Store(countryBenchmarkClassifier(t))
	if os.Getenv("OIMO_COUNTRY_LOAD_CASE") == "board" {
		b, _ := repo.postingOwner(board.ID)
		rows := []identity.NetworkClass{{CIDR: "198.51.100.8/32", Kind: "unknown", Label: "ﾜｶﾗﾝ", Suffix: "0", Provider: "biglobe"}}
		b.readingNetworks.Store(&rows)
	}
	p := defaultReadingPolicy()
	p.Enabled, p.Network.JapanOnly = true, true
	p.Network.DeniedCountries = []string{"US"}
	policy, _ := compileReadingPolicy(p)
	repo.liveReading.Store(&readingSnapshot{Policies: map[string]*compiledReadingPolicy{"site": policy, board.ID.String(): policy}})
	server := httptest.NewUnstartedServer(nil)
	listener := &countryLoadListener{Listener: server.Listener}
	server.Listener = listener
	server.EnableHTTP2 = true
	repo.cfg.Public.BaseURL = "https://" + listener.Addr().String()
	handler := repo.SiteWebHandler(nil)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/__country_stats" {
			_ = json.NewEncoder(w).Encode(countryLoadStats{countryLoadCPU(), listener.rx.Load(), listener.tx.Load()})
			return
		}
		r.RemoteAddr = "198.51.100.8:12345"
		handler.ServeHTTP(w, r)
	})
	server.StartTLS()
	defer server.Close()
	if path := os.Getenv("OIMO_COUNTRY_PROFILE"); path != "" {
		f, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			t.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}
	ready, _ := json.Marshal(map[string]string{"url": server.URL, "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))})
	fmt.Println("COUNTRY_LOAD_READY=" + string(ready))
	_, _ = io.Copy(io.Discard, os.Stdin)
}

// TestCountryPermissionLoad は全応答を照合し、別プロセスのserver CPUとTLS socket量を記録する。
func TestCountryPermissionLoad(t *testing.T) {
	if os.Getenv("OIMO_COUNTRY_LOAD") != "1" {
		t.Skip("set OIMO_COUNTRY_LOAD=1 for isolated measurement")
	}
	runtime.GOMAXPROCS(2)
	n, _ := strconv.Atoi(os.Getenv("OIMO_COUNTRY_REQUESTS"))
	if n == 0 {
		n = 20000
	}
	if n < 1 || n > 1000000 {
		t.Fatal("invalid request count")
	}
	args := []string{os.Args[0], "-test.run=^TestCountryPermissionLoadServer$", "-test.timeout=3m"}
	if cpus := os.Getenv("OIMO_COUNTRY_SERVER_CPUS"); cpus != "" {
		args = append([]string{"taskset", "-c", cpus}, args...)
	}
	cmd := exec.CommandContext(t.Context(), args[0], args[1:]...)
	cmd.Env = append(os.Environ(), "OIMO_COUNTRY_LOAD_CHILD=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	scanner := bufio.NewScanner(stdout)
	var ready struct{ URL, Certificate string }
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "COUNTRY_LOAD_READY=") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "COUNTRY_LOAD_READY=")), &ready); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if ready.URL == "" {
		t.Fatal("load server did not start", scanner.Err())
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(ready.Certificate)) {
		t.Fatal("load server certificate")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second}
	get := func(path string) ([]byte, int, int, error) {
		req, _ := http.NewRequestWithContext(t.Context(), "GET", ready.URL+path, nil)
		req.Header.Set("Accept-Encoding", "identity;q=1, gzip;q=0.1")
		res, err := client.Do(req)
		if err != nil {
			return nil, 0, 0, err
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		return body, res.StatusCode, res.ProtoMajor, err
	}
	const path = "/loadtest/SETTING.TXT"
	expected, status, proto, err := get(path)
	if err != nil || status != 200 || proto != 2 {
		t.Fatal("load preflight", status, proto, string(expected), err)
	}
	stats := func() countryLoadStats {
		t.Helper()
		body, status, _, err := get("/__country_stats")
		var v countryLoadStats
		if err != nil || status != 200 || json.Unmarshal(body, &v) != nil {
			t.Fatal("load stats", err)
		}
		return v
	}
	for range 100 {
		body, status, proto, err := get(path)
		if err != nil || status != 200 || proto != 2 || !bytes.Equal(body, expected) {
			t.Fatal("load warmup", status, proto, err)
		}
	}
	before := stats()
	clientCPU := countryLoadCPU()
	latency := make([]float64, n)
	var errors atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	for worker := range 16 {
		wg.Go(func() {
			for index := worker; index < n; index += 16 {
				at := time.Now()
				body, status, proto, err := get(path)
				latency[index] = float64(time.Since(at).Nanoseconds()) / 1e6
				if err != nil || status != 200 || proto != 2 || !bytes.Equal(body, expected) {
					errors.Add(1)
				}
			}
		})
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	clientCPU = countryLoadCPU() - clientCPU
	after := stats()
	sort.Float64s(latency)
	digest := sha256.Sum256(expected)
	result := map[string]any{"requests": n, "success": n - int(errors.Load()), "errors": errors.Load(), "seconds": elapsed, "rps": float64(n) / elapsed, "p50_ms": latency[n/2], "p95_ms": latency[n*95/100], "server_cpu_seconds": after.CPU - before.CPU, "client_cpu_seconds": clientCPU, "socket_rx_bytes": after.RX - before.RX, "socket_tx_bytes": after.TX - before.TX, "body_bytes": len(expected), "body_sha256": hex.EncodeToString(digest[:]), "workers": 16, "server_gomaxprocs": 2, "client_gomaxprocs": 2, "http": 2, "case": os.Getenv("OIMO_COUNTRY_LOAD_CASE")}
	raw, _ := json.Marshal(result)
	fmt.Println("COUNTRY_LOAD_RESULT=" + string(raw))
	transport.CloseIdleConnections()
	stdin.Close()
	if err := cmd.Wait(); err != nil || errors.Load() != 0 {
		t.Fatal("load failed", err, errors.Load())
	}
}
