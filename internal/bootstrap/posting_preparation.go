// 認可済みの独立スレッド候補だけをCPUで構築し、全終了後に所有列で要求順へ適用する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/board"
	"oimobbs/internal/postcapture"
	"runtime"
)

var errPostingPreparing = errors.New("posting preparation pending")

type postingPreparation struct {
	index    int
	ctx      context.Context
	work     func() ([]byte, []byte, *postcapture.Capture, error)
	complete func([]byte, []byte, *postcapture.Capture, error) (any, error)
	release  func()
	result   postingPreparationResult
}

type postingPreparationResult struct {
	frame, capture []byte
	metadata       *postcapture.Capture
	err            error
}

// addPreparation は構築中のメモリと受理枠を保持する。同じkeyの後続は先にfinishする。
func (g *postingGroup) addPreparation(key uint64, work func() ([]byte, []byte, *postcapture.Capture, error), complete func([]byte, []byte, *postcapture.Capture, error) (any, error), release func()) {
	if g.pendingKeys == nil {
		g.pendingKeys = map[uint64]bool{}
	}
	g.pendingKeys[key] = true
	g.preparationWork.Add(1)
	job := &postingPreparation{index: g.current, ctx: g.ctx, work: work, complete: complete, release: release}
	g.preparations = append(g.preparations, job)
	if g.preparationQueue == nil {
		g.preparationQueue = make(chan *postingPreparation, board.MaxBatchOperations)
	}
	if g.preparationWorkerCount < max(0, runtime.GOMAXPROCS(0)-1) {
		queue := g.preparationQueue
		g.preparationWorkerCount++
		g.preparationWorkers.Go(func() {
			for job := range queue {
				g.runPreparation(job)
			}
		})
	}
	g.preparationQueue <- job
}

// finishPreparations は所有列を停止して不変入力だけを並行処理し、入力順に候補を反映する。
// 全構築終了前に予約を返さず、容量不足・再構築時は残りの受理枠も保存せず返却する。
func (g *postingGroup) finishPreparations() {
	if len(g.preparations) == 0 {
		return
	}
	// 収集中の容量不足は先行候補を確定して解放する。適用中の新たな不足だけ残りを再試行する。
	g.full = false
	jobs := g.preparations
	g.preparations = nil
	clear(g.pendingKeys)

	// 所有列も残りの不変構築を処理し、単なるjoin待ちへCPUを残さない。
drain:
	for {
		select {
		case job, ok := <-g.preparationQueue:
			if !ok {
				break drain
			}
			g.runPreparation(job)
		default:
			break drain
		}
	}
	g.preparationWork.Wait()

	current, ctx := g.current, g.ctx
	defer func() { g.current, g.ctx = current, ctx }()
	if g.preparedResults == nil {
		g.preparedResults = map[int]board.BatchResult{}
	}
	for _, job := range jobs {
		g.current, g.ctx = job.index, job.ctx
		job.release()
		r := &job.result
		if g.rebuild || g.full {
			r.err = errPostingRebuild
		}
		value, err := job.complete(r.frame, r.capture, r.metadata, r.err)
		g.preparedResults[job.index] = board.BatchResult{Value: value, Err: err}
		*r = postingPreparationResult{}
	}
}

// reservePreparation は書込みを行わないCPU構築のメモリだけを予約する。
// 実保存候補へ移す際は別途reserveCapacityで現在のディスク空き・安全余白を必ず確認する。
func (b *postingBoard) reservePreparation() (func(), error) {
	if b.reservePreparationMemory == nil {
		return b.reserveCapacity(postingMemoryBytes)
	}
	release, ok := b.reservePreparationMemory(postingMemoryBytes)
	if !ok {
		return nil, errPostingMemory
	}
	return release, nil
}

// joinPreparationWorkers は全構築を終えてからworkerを閉じる。保存より先に呼び、同じ保存群内の小さな構築群ではworkerを再利用する。
func (g *postingGroup) joinPreparationWorkers() {
	if g.preparationQueue == nil {
		return
	}
	close(g.preparationQueue)
	g.preparationWorkers.Wait()
	g.preparationQueue = nil
	g.preparationWorkerCount = 0
}

// runPreparation は一つの私的slotだけを構築し、所有列/workerのどちらでも一度だけ完了を通知する。
func (g *postingGroup) runPreparation(job *postingPreparation) {
	defer g.preparationWork.Done()
	if err := job.ctx.Err(); err != nil {
		job.result.err = err
		return
	}
	job.result.frame, job.result.capture, job.result.metadata, job.result.err = job.work()
}
