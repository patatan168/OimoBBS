// 大きな変換だけを文字境界で分け、全要求で補助workerの上限を共有する。
package textcodec

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

const codecChunkMinimum = 64 << 10
const parallelMinimum = 2 * codecChunkMinimum
const codecMaxWorkers = 4

var activeConversions atomic.Int32
var codecHelpers atomic.Int32

// reserveCodecHelpers は待機せず枠を確保する。同時変換がCPU数を満たせば追加しない。
func reserveCodecHelpers(size int) int {
	cpus := runtime.GOMAXPROCS(0)
	wanted := min(codecMaxWorkers, cpus, size/codecChunkMinimum) - 1
	for wanted > 0 {
		used := codecHelpers.Load()
		available := min(codecMaxWorkers-1, cpus-int(activeConversions.Load())) - int(used)
		n := min(wanted, available)
		if n <= 0 {
			return 0
		}
		if codecHelpers.CompareAndSwap(used, used+int32(n)) {
			return n
		}
	}
	return 0
}

// runCodecChunks は呼出元も1区間を処理し、全worker終了後に枠を返す。
func runCodecChunks(helpers int, work func(int)) {
	var wg sync.WaitGroup
	defer func() {
		wg.Wait()
		codecHelpers.Add(-int32(helpers))
	}()
	for i := 1; i <= helpers; i++ {
		wg.Go(func() { work(i) })
	}
	work(0)
}

// encodeParallel はUTF-8検証も分担し、各区間の専用領域を縮小時は同じ配列内で詰める。
// 十進参照で1区間でも拡大した場合は別配列へ結合し、未読領域の上書きを防ぐ。
func encodeParallel(s string, allow bool, helpers int) ([]byte, error) {
	jobs := helpers + 1
	var bounds [codecMaxWorkers + 1]int
	for i := 1; i < jobs; i++ {
		at := len(s) * i / jobs
		for at < len(s) && !utf8.RuneStart(s[at]) {
			at++
			if at-len(s)*i/jobs > 3 {
				codecHelpers.Add(-int32(helpers))
				return nil, fmt.Errorf("invalid UTF-8")
			}
		}
		bounds[i] = at
	}
	bounds[jobs] = len(s)
	out := make([]byte, len(s))
	var parts [codecMaxWorkers][]byte
	var errs [codecMaxWorkers]error
	var invalid [codecMaxWorkers]bool
	runCodecChunks(helpers, func(i int) {
		start, end := bounds[i], bounds[i+1]
		if !utf8.ValidString(s[start:end]) {
			invalid[i] = true
			return
		}
		parts[i], errs[i] = appendEncoded(out[start:start:end], s[start:end], allow)
	})
	// 元の実装と同じく、先行する変換不能文字より入力全体のUTF-8不正を優先する。
	for i := 0; i < jobs; i++ {
		if invalid[i] {
			return nil, fmt.Errorf("invalid UTF-8")
		}
	}
	total, expanded := 0, false
	for i := 0; i < jobs; i++ {
		if errs[i] != nil {
			return nil, errs[i]
		}
		total += len(parts[i])
		expanded = expanded || len(parts[i]) > bounds[i+1]-bounds[i]
	}
	if expanded {
		out = make([]byte, total)
	}
	at := 0
	for i := 0; i < jobs; i++ {
		at += copy(out[at:], parts[i])
	}
	return out[:at], nil
}

// decodeBounds は直前のlead候補列の偶奇で境界を求める。長い曖昧列は直列へ戻す。
// 不正入力の厳密なエラーは、区間のいずれかが失敗した場合に全体の直列走査で求める。
func decodeBounds(b []byte, jobs int) ([codecMaxWorkers + 1]int, bool) {
	var bounds [codecMaxWorkers + 1]int
	for i := 1; i < jobs; i++ {
		at := len(b) * i / jobs
		start := at
		for start > bounds[i-1] && decodeSingles[b[start-1]] == leadMarker {
			start--
			if at-start > 256 {
				return bounds, false
			}
		}
		bounds[i] = at + (at-start)%2
	}
	bounds[jobs] = len(b)
	return bounds, true
}

// decodeParallel は区間の専有文字列を順に結合する。失敗時は元のエラー位置を維持する。
func decodeParallel(b []byte, prefix, helpers int) (string, error) {
	jobs := helpers + 1
	bounds, ok := decodeBounds(b, jobs)
	if !ok {
		codecHelpers.Add(-int32(helpers))
		return decodeString(b, 0, prefix)
	}
	var parts [codecMaxWorkers]string
	var errs [codecMaxWorkers]error
	runCodecChunks(helpers, func(i int) {
		chunk := b[bounds[i]:bounds[i+1]]
		parts[i], errs[i] = decodeString(chunk, bounds[i], asciiPrefixBytes(chunk))
	})
	total := 0
	for i := 0; i < jobs; i++ {
		if errs[i] != nil {
			return decodeString(b, 0, prefix)
		}
		total += len(parts[i])
	}
	var out strings.Builder
	out.Grow(total)
	for i := 0; i < jobs; i++ {
		out.WriteString(parts[i])
	}
	return out.String(), nil
}
