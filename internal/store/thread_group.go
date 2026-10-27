// 板所有列の本文追記を一つの再実行WALへ同期し、個別WALの同期を有界にまとめる。
package store

import (
	"crypto/sha256"
	"errors"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/parallel"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// ThreadGroupFile は未checkpointの本文を保持する板単位の再実行WAL。
const ThreadGroupFile = ".posting-group.wal"
const maxThreadGroupBytes = 16 << 20

// maxThreadGroupFrames は従来の64batch×64frameと同じ復旧件数の上限。
// 小さいbatchも一件として数え、低密度な到着による早過ぎるcheckpointを避ける。
const maxThreadGroupFrames = 64 * MaxCommitFrames
const maxThreadGroupBatches = maxThreadGroupFrames

// 圧縮前の総量も、従来の64batch×8MiB以内に保つ。
const maxThreadGroupFrameBytes = 64 * (8 << 20)

// ThreadAppend は板所有列が専有するスレッドへの順序付き追記。
type ThreadAppend struct {
	Log    *ThreadLog
	Frames [][]byte
}

type threadGroupWrite struct {
	Key        domain.U64 `json:"key"`
	Generation domain.U64 `json:"generation"`
	Offset     int64      `json:"offset"`
	Block      []byte     `json:"block"`
}

type threadGroupRecord struct {
	Owner  domain.ID          `json:"owner"`
	Writes []threadGroupWrite `json:"writes"`
}

type threadGroupPlan struct {
	log     *ThreadLog
	state   *domain.Thread
	records []ThreadRecord
	write   threadGroupWrite
	bytes   []byte
}

type threadGroupFile interface {
	SyncWriter
	io.ReaderAt
	Close() error
}

// ThreadCommitGroup は同じ板の所有列専用。再実行WALを同期して本文を耐久化し、
// 個別本文への反映はcheckpointでまとめる。全本文の同期まで再実行WALを残す。
// 公開には別途decision同期が必要。
type ThreadCommitGroup struct {
	mu            sync.Mutex
	parent        string
	owner         domain.ID
	file          threadGroupFile
	bytes         int
	batches       int
	frames        int
	frameBytes    int
	dirty         map[*ThreadLog]bool
	pending       map[*ThreadLog][]threadGroupRange
	reserveBodies func(uint64) (func(), error)
	bodyReleases  []func()
	stopped       bool
	stats         CommitStats
}

// NewThreadCommitGroup は未復旧WALのない板で使う所有者を作る。ファイル作成は初回保存時。
func NewThreadCommitGroup(parent string, owner domain.ID) *ThreadCommitGroup {
	return NewThreadCommitGroupWithReservation(parent, owner, nil)
}

// NewThreadCommitGroupWithReservation は未反映本文のディスク容量をcheckpoint完了まで予約する。
// reserveは所有列で保存前に呼び、返した解放は本文と共有WAL削除の同期成功後だけ呼ぶ。
func NewThreadCommitGroupWithReservation(parent string, owner domain.ID, reserve func(uint64) (func(), error)) *ThreadCommitGroup {
	return &ThreadCommitGroup{parent: parent, owner: owner, dirty: map[*ThreadLog]bool{}, pending: map[*ThreadLog][]threadGroupRange{}, reserveBodies: reserve}
}

// Stats は再実行WAL自体へのWrite/Sync呼出し数を返す。個別本文・親dir同期は含まない。
func (g *ThreadCommitGroup) Stats() CommitStats {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stats
}

// Commit は最大64frame/8MiBを全件検証し、共有WALの耐久化後に論理末尾を進める。
// 個別WALへ反映するまで、共有WAL内の位置だけを保持する。
// 保存開始後の失敗では全参加者を止め、再実行WALを保持する。
func (g *ThreadCommitGroup) Commit(batches []ThreadAppend) CommitResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stopped {
		return CommitResult{Unknown, errors.New("thread commit group stopped")}
	}
	plans, err := g.prepare(batches)
	if err != nil {
		return CommitResult{NotWritten, err}
	}
	record := threadGroupRecord{Owner: g.owner}
	for _, plan := range plans {
		record.Writes = append(record.Writes, plan.write)
	}
	raw, err := encodeThreadGroup(record)
	if err != nil {
		return CommitResult{NotWritten, err}
	}
	count, frameBytes := 0, 0
	for _, batch := range batches {
		count += len(batch.Frames)
		for _, frame := range batch.Frames {
			frameBytes += len(frame)
		}
	}
	if g.bytes+len(raw) > maxThreadGroupBytes || g.frames+count > maxThreadGroupFrames || g.frameBytes+frameBytes > maxThreadGroupFrameBytes {
		if err = g.checkpoint(); err != nil {
			return g.fail(plans, err)
		}
	}
	if g.reserveBodies != nil {
		var size uint64
		for _, plan := range plans {
			size += uint64(len(plan.bytes))
		}
		release, err := g.reserveBodies(size)
		if err != nil {
			return CommitResult{NotWritten, err}
		}
		g.bodyReleases = append(g.bodyReleases, release)
	}
	if err = g.open(); err != nil {
		return g.fail(plans, err)
	}
	g.stats.Writes++
	n, err := g.file.Write(raw)
	if n > 0 {
		g.stats.Bytes += uint64(n)
	}
	if err == nil && n != len(raw) {
		err = io.ErrShortWrite
	}
	if err == nil {
		g.stats.Syncs++
		started := time.Now()
		err = g.file.Sync()
		g.stats.SyncDuration += time.Since(started)
	}
	if err != nil {
		return g.fail(plans, err)
	}
	g.bytes += len(raw)
	g.batches++
	g.frames += count
	g.frameBytes += frameBytes
	// 共有WAL内のblock位置だけを保持し、本文byteをメモリへ滞留させない。
	// 既存の64batch/16MiB上限が範囲数と復旧量も制限する。
	offset := int64(g.bytes - len(raw) + 36)
	for _, plan := range plans {
		g.dirty[plan.log] = true
		plan.log.group = g
		offset += 28
		g.pending[plan.log] = append(g.pending[plan.log], threadGroupRange{offset, len(plan.bytes), checksum(plan.bytes)})
		offset += int64(len(plan.bytes))
	}
	for _, plan := range plans {
		plan.log.state = plan.state
		plan.log.end += int64(len(plan.bytes))
		plan.log.records = append(plan.log.records, plan.records...)
	}
	return CommitResult{Status: Durable}
}

// prepare は所有者・件数・byte予算と全候補を確認し、保存前の私的状態だけを作る。
func (g *ThreadCommitGroup) prepare(batches []ThreadAppend) ([]threadGroupPlan, error) {
	if len(batches) == 0 || len(batches) > MaxCommitFrames {
		return nil, ErrCorrupt
	}
	seen := map[*ThreadLog]bool{}
	count, size := 0, 0
	for _, batch := range batches {
		log := batch.Log
		if log == nil || seen[log] || log.header.Owner != g.owner || filepath.Dir(log.dir) != g.parent || len(batch.Frames) == 0 || log.group != nil && log.group != g {
			return nil, ErrCorrupt
		}
		seen[log] = true
		log.writer.mu.Lock()
		stopped := log.writer.stopped
		log.writer.mu.Unlock()
		if stopped {
			return nil, errors.New("thread writer stopped")
		}
		count += len(batch.Frames)
		if count > MaxCommitFrames {
			return nil, ErrCorrupt
		}
		for _, frame := range batch.Frames {
			if len(frame) > (8<<20)-size {
				return nil, ErrCorrupt
			}
			size += len(frame)
		}
	}
	plans := make([]threadGroupPlan, len(batches))
	errs := make([]error, len(batches))
	parallel.CPU(len(batches), func(i int) { plans[i], errs[i] = prepareThreadGroup(batches[i]) })
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return plans, nil
}

// prepareThreadGroup は従来と同じframe適用・符号化を使い、未公開の末尾候補を作る。
func prepareThreadGroup(batch ThreadAppend) (threadGroupPlan, error) {
	plan := threadGroupPlan{log: batch.Log, state: batch.Log.state}
	for _, raw := range batch.Frames {
		frame, err := decodeFrameLayout(raw)
		if err != nil {
			return plan, err
		}
		var records []ThreadRecord
		plan.state, records, err = applyFrameRecords(plan.state, frame, sha256.Sum256(raw))
		if err != nil {
			// 型検査が先に失敗しても、不正JSONの破損分類を失わない。
			if syntax := validateFrameJSON(frame); syntax != nil {
				err = syntax
			}
			return plan, err
		}
		plan.records = append(plan.records, records...)
	}
	block, err := EncodeWALBlock(batch.Frames)
	plan.bytes = block
	plan.write = threadGroupWrite{domain.U64(batch.Log.header.Key), domain.U64(batch.Log.header.Generation), batch.Log.end, block}
	return plan, err
}

// open は未復旧WALを上書きせず、初回の新規file名を本文の書込前に永続化する。
func (g *ThreadCommitGroup) open() error {
	if g.file != nil {
		return nil
	}
	path := filepath.Join(g.parent, ThreadGroupFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	g.file = file
	return SyncDirectory(g.parent)
}

// fail は保存開始後の結果を不明として固定し、同じ候補の再書込を禁止する。
func (g *ThreadCommitGroup) fail(plans []threadGroupPlan, err error) CommitResult {
	g.stopped = true
	for _, plan := range plans {
		plan.log.writer.mu.Lock()
		plan.log.writer.stopped = true
		plan.log.writer.mu.Unlock()
	}
	return CommitResult{Unknown, err}
}

// Checkpoint は全dirty本文を同期してから共有WALを削除し、親dirを同期する。
// 失敗時は再実行情報を捨てず、以後の保存・世代切替・バックアップを拒否する。
func (g *ThreadCommitGroup) Checkpoint() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checkpoint()
}

func (g *ThreadCommitGroup) checkpoint() error {
	if g.stopped {
		return errors.New("thread commit group stopped")
	}
	if g.file == nil {
		return nil
	}
	if err := g.flushBodies(); err != nil {
		g.stopped = true
		return err
	}
	if err := g.syncBodies(); err != nil {
		g.stopped = true
		return err
	}
	if err := g.file.Close(); err != nil {
		g.stopped = true
		return err
	}
	g.file = nil
	if err := removeThreadGroup(g.parent); err != nil {
		g.stopped = true
		return err
	}
	for log := range g.dirty {
		log.group = nil
	}
	clear(g.dirty)
	clear(g.pending)
	for _, release := range g.bodyReleases {
		if release != nil {
			release()
		}
	}
	g.bodyReleases = nil
	g.bytes, g.batches, g.frames, g.frameBytes = 0, 0, 0, 0
	return nil
}

// syncBodies は独立した本文だけを有界に並行同期し、全worker完了まで共有WALを保持する。
func (g *ThreadCommitGroup) syncBodies() error {
	logs := make([]*ThreadLog, 0, len(g.dirty))
	for log := range g.dirty {
		logs = append(logs, log)
	}
	errs := make([]error, len(logs))
	count := min(len(logs), max(16, runtime.GOMAXPROCS(0)*2))
	var workers sync.WaitGroup
	for worker := range count {
		workers.Go(func() {
			for index := worker; index < len(logs); index += count {
				writer := logs[index].writer
				writer.mu.Lock()
				writer.stats.Syncs++
				errs[index] = writer.file.Sync()
				writer.mu.Unlock()
			}
		})
	}
	workers.Wait()
	return errors.Join(errs...)
}

// Close は正常時にcheckpointし、結果不明時は再実行WALを残してdescriptorだけ閉じる。
func (g *ThreadCommitGroup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	err := g.checkpoint()
	if g.file != nil {
		err = errors.Join(err, g.file.Close())
		g.file = nil
	}
	return err
}

// Flush は個別WALを直接変更・捕捉する前に、参加した共有保存のcheckpointを完了する。
func (t *ThreadLog) Flush() error {
	if t.group != nil {
		return t.group.Checkpoint()
	}
	return nil
}

// removeThreadGroup は全本文の耐久化後にだけ呼び、再実行WAL名の削除を同期する。
func removeThreadGroup(parent string) error {
	if err := os.Remove(filepath.Join(parent, ThreadGroupFile)); err != nil {
		return err
	}
	return SyncDirectory(parent)
}
