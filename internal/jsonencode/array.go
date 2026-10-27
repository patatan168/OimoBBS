// 大きな生成済み配列だけを私的なbufferへ分担し、元の要素順に連結する。
package jsonencode

import (
	"oimobbs/internal/parallel"
	"runtime"
	"slices"
)

// TryArray は大きい配列の内側を並列符号化する。括弧とnilは生成元が処理する。
// appendRangeは[start,end)を範囲内のcomma付きで書く。入力変更などの副作用を持たせない。
// 小配列・上界計算・worker不足ではfalseを返し、wを変更しない。
func TryArray(w *Writer, count int, appendRange func(*Writer, int, int)) bool {
	if !w.CanParallelArray(count) {
		return false
	}
	sample := Writer{serial: true}
	appendRange(&sample, 0, 4)
	estimate := len(sample.Bytes) / 4 * count
	workers := min(runtime.GOMAXPROCS(0), estimate/(64<<10), count/32)
	if workers < 2 {
		return false
	}
	parts := make([]Writer, workers)
	parts[0] = sample
	if !parallel.TryCPU(workers, func(i int) {
		part := &parts[i]
		part.serial = true
		capacity := min(estimate/workers+1, 1<<20)
		if i != 0 {
			part.Bytes = make([]byte, 0, capacity)
		} else {
			part.Bytes = slices.Grow(part.Bytes, max(0, capacity-len(part.Bytes)))
			part.Literal(",")
		}
		start := 4 + (count-4)*i/workers
		end := 4 + (count-4)*(i+1)/workers
		appendRange(part, start, end)
	}) {
		return false
	}
	size := workers - 1
	for i := range parts {
		size += len(parts[i].Bytes)
	}
	w.Bytes = slices.Grow(w.Bytes, size)
	for i := range parts {
		if i > 0 {
			w.Literal(",")
		}
		w.Bytes = append(w.Bytes, parts[i].Bytes...)
		if parts[i].Err != nil {
			w.Err = parts[i].Err
		}
	}
	return true
}

// CanParallelArray は分担候補を判定し、小配列でcallback自体がheapへ確保されることを避ける。
// trueでも本文の推定量や共有worker枠によってTryArrayが逐次処理へ戻る場合がある。
func (w *Writer) CanParallelArray(count int) bool {
	return count >= 128 && !w.BoundOnly && !w.serial && runtime.GOMAXPROCS(0) > 1
}
