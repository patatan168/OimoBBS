// 利用可能なCPU・メモリから保持・生成・新規受付の予算を決める。
package bootstrap

import (
	"errors"
	"log/slog"
	"net/http"
	"oimobbs/internal/platform"
	"os"
	"runtime"
	"sync"
)

const representationWorkerBytes uint64 = 8 << 20
const postingMemoryBytes uint64 = 16 << 20

// errPostingMemory は保存開始前に作業メモリを予約できなかったことを示す。
var errPostingMemory = errors.New("posting memory unavailable")

// RuntimeResourceStatus は監視済みのメモリ・作業予約・受付抑制を管理画面へ公開する。
type RuntimeResourceStatus struct {
	CPUs     int                  `json:"gomaxprocs"`
	Memory   platform.MemoryState `json:"memory"`
	Reserved uint64               `json:"reserved_bytes"`
	Rejected uint64               `json:"rejected_memory_reservations"`
}

// RuntimeResources は要求本文を含まない資源集計を返す。観測値は監視周期で更新する。
func (r *Repository) RuntimeResources() RuntimeResourceStatus {
	status := RuntimeResourceStatus{CPUs: runtime.GOMAXPROCS(0), Reserved: r.memoryReserved.Load(), Rejected: r.memoryRejected.Load()}
	if memory := r.memory.Load(); memory != nil {
		status.Memory = *memory
	}
	return status
}

// representationResources はメモリの八分の一ずつを保持と生成器へ割り当てる。
// headroomが減ると保持を縮め、新しい生成を停止する。実行中の生成は取り消さない。
func representationResources(memory platform.MemoryState, cpus int) (uint64, int) {
	cache := memory.Limit / 8
	workers := max(1, min(cpus, int(memory.Limit/8/representationWorkerBytes)))
	reserve := max(uint64(16<<20), memory.Limit/16)
	if memory.Headroom <= reserve {
		return 0, 0
	}
	spare := memory.Headroom - reserve
	cache = min(cache, spare/2)
	workers = min(workers, int(spare/representationWorkerBytes))
	if workers == 0 {
		return 0, 0
	}
	return cache, workers
}

// memoryHandler は本文生成前に要求の作業領域を予約し、送信完了まで保持する。
// 不足時は待機列を増やさず503を返す。管理経路は別枠のまま残す。
func (r *Repository) memoryHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// 大きい生成・検索・投稿準備は別途予約する。共有DATの読取りまで重い生成と同額にしない。
		working := uint64(1 << 20)
		progress := representationWorkerBytes
		if req.Method == "POST" {
			working = 4 << 20
			progress = postingMemoryBytes
		} else if r.postingIO.hasPosts() {
			progress = postingMemoryBytes
		}
		// 新しい入力が全予算を使い、既に受け付けた投稿・生成が進めなくなることを防ぐ。
		release, ok := r.reserveMemoryWithProgress(working, progress)
		if !ok {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "混み合っています。しばらくしてからお試しください。", http.StatusServiceUnavailable)
			return
		}
		defer release()
		next.ServeHTTP(w, req)
	})
}

// representationResources は監視済みのメモリと現在のCPU並列数を参照する。
func (r *Repository) representationResources() (uint64, int) {
	memory := r.memory.Load()
	if memory == nil {
		return 0, 1
	}
	return representationResources(*memory, runtime.GOMAXPROCS(0))
}

// refreshMemory は監視周期で予算を再評価し、逼迫時は保持を縮めて新規生成を抑える。
func (r *Repository) refreshMemory() {
	memory := platform.ObserveMemory()
	// 受付を止めると割当も止まり、通常のGC開始条件へ届かないことがある。
	// 保存中の予約がなく、GC以後の増分が大きい場合だけ一度回収して再観測する。
	if needsMemoryCollection(memory, r.memoryReserved.Load()) {
		runtime.GC()
		memory = platform.ObserveMemory()
	}
	r.memory.Store(&memory)
	if r.feedCompression != nil {
		r.feedCompression.RefreshResources()
	}
	if os.Getenv("OIMO_RESOURCE_DIAGNOSTICS") == "1" {
		slog.Info("runtime_resources", "resources", r.RuntimeResources())
	}
}

func needsMemoryCollection(memory platform.MemoryState, reserved uint64) bool {
	margin := max(uint64(16<<20), memory.Limit/16)
	return reserved == 0 && memory.Headroom < margin+titleSearchReservation && memory.Allocated > memory.Live && memory.Allocated-memory.Live >= margin
}

func (r *Repository) searchMemoryBudget() int64 {
	if memory := r.memory.Load(); memory != nil {
		return int64(max(uint64(titleSearchReservation), memory.Limit/8/uint64(titleSearchReservation)*uint64(titleSearchReservation)))
	}
	return titleSearchBudget
}

func (r *Repository) searchParallelism() int {
	if r.memory.Load() == nil {
		return 4
	}
	return max(1, min(runtime.GOMAXPROCS(0), int(r.searchMemoryBudget()/titleSearchReservation)))
}

// reserveMemory は観測済みの余裕から、新しい重い処理の最大作業量を予約する。
// 観測後に始まった処理も同じ台帳で数え、監視周期中の一斉開始を抑える。
func (r *Repository) reserveMemory(bytes uint64) (func(), bool) {
	return r.reserveMemoryWithProgress(bytes, 0)
}

func (r *Repository) reserveMemoryWithProgress(bytes, progress uint64) (func(), bool) {
	memory := r.memory.Load()
	if memory == nil {
		return func() {}, true
	}
	margin := max(uint64(16<<20), memory.Limit/16) + progress
	for {
		held := r.memoryReserved.Load()
		if memory.Headroom <= margin || held > memory.Headroom-margin || bytes > memory.Headroom-margin-held {
			r.memoryRejected.Add(1)
			return nil, false
		}
		if r.memoryReserved.CompareAndSwap(held, held+bytes) {
			break
		}
	}
	var once sync.Once
	return func() { once.Do(func() { r.memoryReserved.Add(^(bytes - 1)) }) }, true
}
