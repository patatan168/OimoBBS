// 一回の同期に含む独立した既存WAL blockの圧縮だけを、CPU数以内へ分担する。
package store

import (
	"bytes"
	"oimobbs/internal/parallel"
	"runtime"
)

// encodeParallelWAL は合計64frame/8MiBを維持し、大きい群を既存blockへ分ける。
// 4CPU以下は16frameで圧縮範囲を広げ、5CPU以上では8frameで従来の並列性を保つ。
// frame・圧縮形式・各blockの探索精度は変更しない。既存readerは連続blockとして読み込める。
func encodeParallelWAL(frames [][]byte) ([]byte, error) {
	if len(frames) == 0 || len(frames) > MaxCommitFrames {
		return nil, ErrCorrupt
	}
	size := 0
	for _, frame := range frames {
		if len(frame) > (8<<20)-size {
			return nil, ErrCorrupt
		}
		size += len(frame)
	}
	if len(frames) < 16 || size < 64<<10 {
		return EncodeWALBlock(frames)
	}
	chunk := 16
	if runtime.GOMAXPROCS(0) > 4 {
		chunk = 8
	}
	count := (len(frames) + chunk - 1) / chunk
	blocks := make([][]byte, count)
	errs := make([]error, count)
	parallel.CPU(count, func(i int) { blocks[i], errs[i] = EncodeWALBlock(frames[i*chunk : min(len(frames), (i+1)*chunk)]) })
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return bytes.Join(blocks, nil), nil
}

// encodeParallelWALSeries は非必須ログの既存64frame境界を保ち、最大四blockだけ並行圧縮する。
// 各blockのbyte列と列全体8MiBの上限は直列のencodeWALSeriesと同じ。
func encodeParallelWALSeries(frames [][]byte) ([]byte, error) {
	if len(frames) <= MaxCommitFrames {
		return encodeWALSeries(frames)
	}
	if len(frames) > MaxCommitSeriesFrames {
		return nil, ErrCorrupt
	}
	total := 0
	for _, frame := range frames {
		if len(frame) > (8<<20)-total {
			return nil, ErrCorrupt
		}
		total += len(frame)
	}
	count := (len(frames) + MaxCommitFrames - 1) / MaxCommitFrames
	blocks := make([][]byte, count)
	errs := make([]error, count)
	parallel.CPU(count, func(i int) {
		blocks[i], errs[i] = EncodeWALBlock(frames[i*MaxCommitFrames : min(len(frames), (i+1)*MaxCommitFrames)])
	})
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return bytes.Join(blocks, nil), nil
}
