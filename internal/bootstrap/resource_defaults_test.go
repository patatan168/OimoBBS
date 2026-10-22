// 資源の大小、逼迫時の縮小、重い処理の同時受付と解放を検証する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/platform"
	"sync"
	"testing"
)

func TestAdaptiveRepresentationResources(t *testing.T) {
	for _, tc := range []struct {
		name             string
		memory, headroom uint64
		cpus             int
		cache            uint64
		workers          int
	}{
		{name: "small-single-core", memory: 192 << 20, headroom: 128 << 20, cpus: 1, cache: 24 << 20, workers: 1},
		{name: "small-many-core", memory: 192 << 20, headroom: 128 << 20, cpus: 64, cache: 24 << 20, workers: 3},
		{name: "large-many-core", memory: 12 << 30, headroom: 8 << 30, cpus: 64, cache: 1536 << 20, workers: 64},
		{name: "tiny", memory: 32 << 20, headroom: 24 << 20, cpus: 8, cache: 4 << 20, workers: 1},
		{name: "pressure", memory: 768 << 20, headroom: 32 << 20, cpus: 8, cache: 0, workers: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, workers := representationResources(platform.MemoryState{Limit: tc.memory, Headroom: tc.headroom}, tc.cpus)
			if cache != tc.cache || workers != tc.workers {
				t.Fatalf("cache=%d workers=%d want=%d/%d", cache, workers, tc.cache, tc.workers)
			}
		})
	}
}

func TestMemoryReservationsConcurrentAndRecoverable(t *testing.T) {
	repo := &Repository{}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 64 << 20})
	var group sync.WaitGroup
	releases := make(chan func(), 128)
	for range 128 {
		group.Go(func() {
			if release, ok := repo.reserveMemory(1 << 20); ok {
				releases <- release
			}
		})
	}
	group.Wait()
	close(releases)
	if len(releases) != 48 || repo.memoryReserved.Load() != 48<<20 {
		t.Fatal("overcommit or lost capacity", len(releases), repo.memoryReserved.Load())
	}
	for release := range releases {
		release()
		release()
	}
	if repo.memoryReserved.Load() != 0 {
		t.Fatal("reservation leak")
	}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 16 << 20})
	if release, ok := repo.reserveMemory(1); ok {
		release()
		t.Fatal("pressure accepted")
	}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 64 << 20})
	if release, ok := repo.reserveMemory(1 << 20); ok {
		release()
	} else {
		t.Fatal("recovery refused")
	}
}

func TestPublicMemoryAdmissionBeforeWork(t *testing.T) {
	repo := &Repository{}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 16 << 20})
	calls := 0
	handler := repo.memoryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "http://example.invalid/", nil))
	if response.Code != 503 || response.Header().Get("Retry-After") != "1" || calls != 0 {
		t.Fatal("work started under pressure", response.Code, calls)
	}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 64 << 20})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "http://example.invalid/", nil))
	if response.Code != 204 || calls != 1 || repo.memoryReserved.Load() != 0 {
		t.Fatal("recovery or release failed")
	}
}

// 大きな作業が残っていても軽い読取りは進め、重い入力要求は先に抑える。
func TestPublicMemoryAdmissionKeepsLightReadsAvailable(t *testing.T) {
	repo := &Repository{}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 41 << 20})
	release, ok := repo.reserveMemory(8 << 20)
	if !ok {
		t.Fatal("fixture reservation")
	}
	defer release()
	handler := repo.memoryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	for _, tc := range []struct {
		method string
		status int
	}{{"GET", 204}, {"POST", 503}} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(tc.method, "http://example.invalid/", nil))
		if response.Code != tc.status {
			t.Fatal(tc.method, response.Code)
		}
	}
	if repo.memoryReserved.Load() != 8<<20 {
		t.Fatal("request reservation leaked")
	}
}

func TestReadProgressReserveFollowsPendingPosts(t *testing.T) {
	repo := &Repository{}
	repo.memory.Store(&platform.MemoryState{Limit: 256 << 20, Headroom: 33 << 20})
	release, ok := repo.reserveMemory(8 << 20)
	if !ok {
		t.Fatal("fixture reservation")
	}
	defer release()
	handler := repo.memoryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	request := func() int {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "http://example.invalid/", nil))
		return response.Code
	}
	if status := request(); status != 204 {
		t.Fatal("idle read unnecessarily blocked", status)
	}
	releasePost := repo.postingIO.holdPost()
	status := request()
	releasePost()
	if status != 503 {
		t.Fatal("pending posting lost its progress reserve", status)
	}
	if status := request(); status != 204 {
		t.Fatal("read did not recover after posting drain", status)
	}
}

// 受付制限により割当が止まっても、GC後の増分を回収して受付へ戻れる条件を検証する。
func TestPressureCollectionDoesNotRepeatWithoutGrowth(t *testing.T) {
	state := platform.MemoryState{Limit: 192 << 20, Headroom: 24 << 20, Live: 96 << 20, Allocated: 160 << 20}
	if !needsMemoryCollection(state, 0) {
		t.Fatal("stalled allocation not collected")
	}
	if needsMemoryCollection(state, postingMemoryBytes) {
		t.Fatal("collection scheduled during reserved work")
	}
	state.Allocated = state.Live
	if needsMemoryCollection(state, 0) {
		t.Fatal("collection repeated without allocation growth")
	}
	state.Allocated = 160 << 20
	state.Headroom = 96 << 20
	if needsMemoryCollection(state, 0) {
		t.Fatal("unnecessary pressure collection")
	}
}
