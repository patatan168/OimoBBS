// 制御バッチの状態非依存デコードだけをCPU数に応じて分担し、適用順序を所有列へ残す。
package store

import (
	"runtime"
	"sync"
)

type preparedControlOperation struct {
	firstSeq uint64
	op       ControlOperation
	err      error
}

// decodeControlFrames は入力を変更せず各slotへ結果を書き、全workerの終了後に返す。
// 小さいバッチではgoroutineを作らず、最大byte数の検査は呼出元で先に済ませる。
func decodeControlFrames(frames [][]byte, totalBytes int) []preparedControlOperation {
	decoded := make([]preparedControlOperation, len(frames))
	workers := 1
	if len(frames) >= 8 && totalBytes >= 32<<10 {
		workers = min(runtime.GOMAXPROCS(0), len(frames)/4)
	}
	if workers == 1 {
		for i, frame := range frames {
			decoded[i] = decodeControlCandidate(frame)
		}
		return decoded
	}
	decode := func(worker int) {
		for i := worker; i < len(frames); i += workers {
			decoded[i] = decodeControlCandidate(frames[i])
		}
	}
	var pending sync.WaitGroup
	for worker := 1; worker < workers; worker++ {
		pending.Go(func() { decode(worker) })
	}
	decode(0)
	pending.Wait()
	return decoded
}

func decodeControlCandidate(raw []byte) preparedControlOperation {
	f, err := decodeFrameView(raw)
	if err != nil || len(f.Records) != 1 {
		return preparedControlOperation{err: ErrCorrupt}
	}
	op, err := decodeControlOperation(f)
	if err == nil && (len(op.Mutations) < 1 || len(op.Mutations) > 256) {
		err = ErrCorrupt
	}
	return preparedControlOperation{f.FirstSeq, op, err}
}
