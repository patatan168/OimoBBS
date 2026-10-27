// 実cgroup下のメモリ圧迫・受付停止・回復を同じRepositoryで検証する。
package bootstrap

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/compat"
	"oimobbs/internal/platform"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// TestResourcePressureProcess は隔離コンテナ用。通常のテストでホストのメモリを埋めない。
func TestResourcePressureProcess(t *testing.T) {
	if os.Getenv("OIMO_RESOURCE_PRESSURE_PROBE") != "1" {
		t.Skip("isolated cgroup probe only")
	}
	maximum, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		t.Fatal("finite cgroup required", err)
	}
	bytes, err := strconv.ParseUint(strings.TrimSpace(string(maximum)), 10, 64)
	if err != nil || bytes == 0 || bytes > 8<<30 {
		t.Fatal("pressure probe requires cgroup memory limit at most 8GiB")
	}
	platform.ConfigureRuntime()
	cfg := testConfig(t)

	if _, err := Initialize(cfg, "資源圧迫試験"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	record := func(phase string) {
		t.Helper()
		memory := repo.memory.Load()
		raw, _ := json.Marshal(struct {
			Phase  string
			CPUs   int
			Memory platform.MemoryState
			Cache  compat.CompressionCacheStatus
		}{phase, runtime.GOMAXPROCS(0), *memory, repo.feedCompression.Status()})
		t.Log(string(raw))
	}
	record("initial")
	// 実際のキャッシュに別々の本文を保持させ、逼迫時の解放対象を作る。
	for i := range 8 {
		_, err := repo.feedCompression.Render(t.Context(), string(rune('a'+i)), func() ([]byte, error) { body := make([]byte, 2<<20); body[0] = 1; return body, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	var pressure [][]byte
	total := uint64(0)
	limit := repo.memory.Load().Limit
	for repo.feedCompression.Status().Workers != 0 && total+4<<20 < limit {
		block := make([]byte, 4<<20)
		for i := 0; i < len(block); i += 4096 {
			block[i] = 1
		}
		pressure = append(pressure, block)
		total += uint64(len(block))
		repo.refreshMemory()
	}
	record("pressure")
	if status := repo.feedCompression.Status(); status.Workers != 0 || status.Used != 0 {
		t.Fatal("cache did not yield", status)
	}
	if _, err := repo.feedCompression.Render(t.Context(), "denied", func() ([]byte, error) { t.Error("unreserved build"); return nil, nil }); !errors.Is(err, compat.ErrCompressionCapacity) {
		t.Fatal(err)
	}
	if release, err := repo.reservePosting(); !errors.Is(err, errPostingMemory) {
		if release != nil {
			release()
		}
		t.Fatal("posting memory refusal lost", err)
	}
	handler := repo.memoryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "http://example.invalid/", nil))
	if response.Code != 503 {
		t.Fatal("public work accepted under pressure", response.Code)
	}
	runtime.KeepAlive(pressure)
	pressure = nil
	runtime.GC()
	debug.FreeOSMemory()
	repo.refreshMemory()
	record("recovered")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "http://example.invalid/", nil))
	if response.Code != 204 || repo.memoryReserved.Load() != 0 {
		t.Fatal("request did not recover", response.Code)
	}
	if _, err := repo.feedCompression.Render(t.Context(), "recovered", func() ([]byte, error) { return []byte("ok"), nil }); err != nil {
		t.Fatal(err)
	}
	for _, file := range []string{"memory.max", "memory.peak", "memory.events", "cpu.max"} {
		if raw, err := os.ReadFile("/sys/fs/cgroup/" + file); err == nil {
			t.Log(file, string(raw))
		}
	}
}

// TestResourceCollectionWithReservedWorkProcess は512MiB cgroupで未回収領域だけを回収し、
// 実行中の予約と生存データを維持したまま受付の余裕が戻ることを確認する。
func TestResourceCollectionWithReservedWorkProcess(t *testing.T) {
	if os.Getenv("OIMO_RESOURCE_PRESSURE_PROBE") != "1" {
		t.Skip("isolated cgroup probe only")
	}
	raw, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		t.Fatal(err)
	}
	maximum, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || maximum != 512<<20 {
		t.Fatal("512MiB cgroup required")
	}
	platform.ConfigureRuntime()
	previous := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(previous) })
	runtime.GC()
	repo := &Repository{}
	repo.refreshMemory()
	release, ok := repo.reserveMemory(2 * titleSearchReservation)
	if !ok {
		t.Fatal("initial working reservation")
	}
	defer release()
	limit := repo.memory.Load().Limit
	live := make([]byte, int(limit/2))
	for i := 0; i < len(live); i += 4096 {
		live[i] = 1
	}
	func() {
		garbage := make([]byte, int(limit/4+representationWorkerBytes))
		for i := 0; i < len(garbage); i += 4096 {
			garbage[i] = 1
		}
		runtime.KeepAlive(garbage)
	}()
	before := platform.ObserveMemory()
	if before.Headroom >= limit/4 || before.Allocated <= before.Live+32<<20 {
		t.Fatal("fixture did not reach collection pressure", before)
	}
	// 未回収の領域を含む観測を公開し、予約が残る状態で実際に受付が止まることを確認する。
	repo.memory.Store(&before)
	handler := repo.memoryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	request := func() int {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://example.invalid/", nil))
		return response.Code
	}
	if status := request(); status != 503 {
		t.Fatal("fixture admission was not blocked", status)
	}
	var gcBefore, gcAfter runtime.MemStats
	runtime.ReadMemStats(&gcBefore)
	repo.refreshMemory()
	runtime.ReadMemStats(&gcAfter)
	after := repo.memory.Load()
	if gcAfter.NumGC <= gcBefore.NumGC || after.Headroom <= before.Headroom+32<<20 {
		t.Fatal("garbage was not reclaimed", before, after)
	}
	if repo.memoryReserved.Load() != 2*titleSearchReservation {
		t.Fatal("live reservation was discarded")
	}
	if status := request(); status != 204 {
		t.Fatal("collection did not restore admission", status)
	}
	for i := 0; i < len(live); i += 4096 {
		if live[i] != 1 {
			t.Fatal("live work corrupted")
		}
	}
	runtime.KeepAlive(live)
	t.Logf("headroom before=%d after=%d; GC before=%d after=%d; reservation=%d", before.Headroom, after.Headroom, gcBefore.NumGC, gcAfter.NumGC, repo.memoryReserved.Load())
}
