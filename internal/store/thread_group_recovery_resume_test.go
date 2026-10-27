// 復旧済み本文の保持と、復旧I/O障害時に再実行WALを失わず再開できることを検査する。
package store

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"oimobbs/internal/domain"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type replayFixture struct {
	parent    string
	owner     domain.ID
	plans     []*threadGroupReplay
	authorize func(uint64, []byte) error
	wantDAT   map[uint64][]byte
}

// newReplayFixture は三つの実本文と二群の耐久WALを作り、本文ごとに既存の復旧済みprefixを残す。
func newReplayFixture(t *testing.T, present []int) *replayFixture {
	t.Helper()
	g, batches, create := newThreadGroupTest(t)
	frames := map[uint64][][]byte{}
	wantDAT := map[uint64][]byte{}
	for seq := uint32(2); seq <= 3; seq++ {
		for i := range batches {
			raw := packReply(t, create, seq)
			batches[i].Frames = [][]byte{raw}
			key := batches[i].Log.header.Key
			frames[key] = append(frames[key], raw)
		}
		if result := g.Commit(batches); result.Status != Durable {
			t.Fatal(result)
		}
	}
	for _, batch := range batches {
		wantDAT[batch.Log.header.Key] = bytes.Join(batch.Log.State().Lines, nil)
	}
	if err := g.file.Close(); err != nil {
		t.Fatal(err)
	}
	g.file, g.stopped = nil, true
	for _, batch := range batches {
		if err := batch.Log.file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	authorize := func(key uint64, raw []byte) error {
		for _, want := range frames[key] {
			if bytes.Equal(raw, want) {
				return nil
			}
		}
		return ErrCorrupt
	}
	raw, err := os.ReadFile(filepath.Join(g.parent, ThreadGroupFile))
	if err != nil {
		t.Fatal(err)
	}
	records, err := decodeThreadGroups(raw)
	if err != nil {
		t.Fatal(err)
	}
	plans, err := prepareThreadGroupReplay(records, g.owner, authorize)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeThreadGroupReplays(plans) })
	for i, plan := range plans {
		path := filepath.Join(g.parent, fmt.Sprint(plan.key), "delta-000001.wal")
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		offset := plan.start
		for _, block := range plan.blocks[:present[i]] {
			if _, err = f.WriteAt(block, offset); err != nil {
				f.Close()
				t.Fatal(err)
			}
			offset += int64(len(block))
		}
		err = errors.Join(f.Sync(), f.Close())
		if err != nil {
			t.Fatal(err)
		}
		if err = plan.open(g.parent, g.owner); err != nil {
			t.Fatal(err)
		}
	}
	return &replayFixture{parent: g.parent, owner: g.owner, plans: plans, authorize: authorize, wantDAT: wantDAT}
}

type replayFaultFile struct {
	threadReplayFile
	writes, syncs, closes                                      int
	bytes                                                      int
	truncateErr, seekErr, writeErr, syncErr, closeErr, readErr error
	short                                                      bool
	truncateAt                                                 []int64
	afterWrite, afterSync, afterClose                          func()
}

func (f *replayFaultFile) Write(raw []byte) (int, error) {
	f.writes++
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	if f.short {
		raw = raw[:len(raw)/2]
	}
	n, err := f.threadReplayFile.Write(raw)
	f.bytes += n
	if err == nil && f.afterWrite != nil {
		f.afterWrite()
	}
	return n, err
}
func (f *replayFaultFile) Sync() error {
	f.syncs++
	if f.syncErr != nil {
		return f.syncErr
	}
	err := f.threadReplayFile.Sync()
	if err == nil && f.afterSync != nil {
		f.afterSync()
	}
	return err
}
func (f *replayFaultFile) Close() error {
	f.closes++
	err := errors.Join(f.threadReplayFile.Close(), f.closeErr)
	if err == nil && f.afterClose != nil {
		f.afterClose()
	}
	return err
}
func (f *replayFaultFile) Truncate(n int64) error {
	f.truncateAt = append(f.truncateAt, n)
	if f.truncateErr != nil {
		return f.truncateErr
	}
	return f.threadReplayFile.Truncate(n)
}
func (f *replayFaultFile) Seek(n int64, w int) (int64, error) {
	if f.seekErr != nil {
		return 0, f.seekErr
	}
	return f.threadReplayFile.Seek(n, w)
}
func (f *replayFaultFile) ReadAt(raw []byte, n int64) (int, error) {
	if f.readErr != nil {
		return 0, f.readErr
	}
	return f.threadReplayFile.ReadAt(raw, n)
}

func TestThreadGroupRecoveryReusesVerifiedPrefix(t *testing.T) {
	f := newReplayFixture(t, []int{1, 2, 0})
	counters := []*replayFaultFile{}
	for _, plan := range f.plans {
		file := &replayFaultFile{threadReplayFile: plan.file}
		plan.file = file
		counters = append(counters, file)
	}
	if err := replayThreadGroupPlans(f.parent, f.plans); err != nil {
		t.Fatal(err)
	}
	for i, present := range []int{1, 2, 0} {
		want := 0
		for _, block := range f.plans[i].blocks[present:] {
			want += len(block)
		}
		if counters[i].bytes != want {
			t.Errorf("thread %d rewrote verified bytes: wrote=%d want=%d", i, counters[i].bytes, want)
		}
		t.Logf("thread=%d retained_blocks=%d write_bytes=%d syncs=%d closes=%d", f.plans[i].key, present, counters[i].bytes, counters[i].syncs, counters[i].closes)
		if counters[i].syncs != 1 || counters[i].closes != 1 {
			t.Errorf("thread %d missing Sync/Close: %+v", i, counters[i])
		}
	}
	verifyReplayThreads(t, f)
}

func TestThreadGroupRecoveryKeepsRedoOnCloseFailure(t *testing.T) {
	f := newReplayFixture(t, []int{0, 0, 0})
	injected := errors.New("close failed")
	f.plans[0].file = &replayFaultFile{threadReplayFile: f.plans[0].file, closeErr: injected}
	if err := replayThreadGroupPlans(f.parent, f.plans); !errors.Is(err, injected) {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); err != nil {
		t.Fatal("redo lost before all closes succeeded", err)
	}
	if err := RecoverThreadCommitGroup(f.parent, f.owner, f.authorize); err != nil {
		t.Fatal("retry failed", err)
	}
}

func TestThreadGroupRecoveryCorrectBodiesNeedNoWrite(t *testing.T) {
	f := newReplayFixture(t, []int{2, 2, 2})
	for _, p := range f.plans {
		p.file = &replayFaultFile{threadReplayFile: p.file, writeErr: syscall.ENOSPC}
	}
	if err := replayThreadGroupPlans(f.parent, f.plans); err != nil {
		t.Fatal("matching bodies required extra write", err)
	}
}

// verifyReplayThreads は公開復旧入口の後に全本文の採番・読み込みを再検査する。
func verifyReplayThreads(t *testing.T, f *replayFixture) {
	t.Helper()
	for _, p := range f.plans {
		log, err := OpenThread(f.parent, f.owner, p.key)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(bytes.Join(log.State().Lines, nil), f.wantDAT[p.key]) {
			t.Error("recovered DAT differs", p.key)
		}
		if log.State().Revision != 3 {
			t.Error("recovered revision", p.key, log.State().Revision)
		}
		if err = log.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("redo not removed after successful recovery", err)
	}
}

func TestThreadGroupRecoveryFaultsRemainRetryable(t *testing.T) {
	for _, phase := range []string{"truncate", "seek", "space", "short", "sync", "close", "read-space"} {
		t.Run(phase, func(t *testing.T) {
			present := []int{0, 0, 0}
			if phase == "read-space" {
				present = []int{2, 2, 2}
			}
			f := newReplayFixture(t, present)
			redoPath := filepath.Join(f.parent, ThreadGroupFile)
			before, err := os.ReadFile(redoPath)
			if err != nil {
				t.Fatal(err)
			}
			var counters []*replayFaultFile
			for _, p := range f.plans {
				file := &replayFaultFile{threadReplayFile: p.file}
				p.file = file
				counters = append(counters, file)
			}
			injected := error(syscall.EIO)
			fault := counters[1]
			switch phase {
			case "truncate":
				fault.truncateErr = injected
			case "seek":
				fault.seekErr = injected
			case "space":
				injected = syscall.ENOSPC
				fault.writeErr = injected
			case "short":
				injected = io.ErrShortWrite
				fault.short = true
			case "sync":
				fault.syncErr = injected
			case "close":
				fault.closeErr = injected
			case "read-space":
				fault.readErr = syscall.EIO
				injected = syscall.ENOSPC
				fault.writeErr = injected
			}
			if err = replayThreadGroupPlans(f.parent, f.plans); !errors.Is(err, injected) {
				t.Fatal("failure hidden", phase, err)
			}
			after, err := os.ReadFile(redoPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("redo changed after failed recovery", phase, err)
			}
			for i, file := range counters {
				if file.closes != 1 {
					t.Error("file not closed exactly once", phase, i, file.closes)
				}

			}
			if err = RecoverThreadCommitGroup(f.parent, f.owner, f.authorize); err != nil {
				t.Fatal("retry failed", phase, err)
			}
			verifyReplayThreads(t, f)
		})
	}
}

func TestThreadGroupRecoveryClosesBeforeRemovingRedo(t *testing.T) {
	f := newReplayFixture(t, []int{2, 2, 2})
	var files []*replayFaultFile
	for _, p := range f.plans {
		file := &replayFaultFile{threadReplayFile: p.file}
		p.file = file
		files = append(files, file)
	}
	for _, file := range files {
		file.afterClose = func() {
			for _, other := range files {
				if other.syncs != 1 {
					t.Error("closed before every body Sync")
				}
			}
			if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); err != nil {
				t.Error("redo removed before Close completed", err)
			}
		}
	}
	if err := replayThreadGroupPlans(f.parent, f.plans); err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.writes != 0 || len(file.truncateAt) != 0 || file.syncs != 1 || file.closes != 1 {
			t.Error("matching body mutated or not synced/closed", file)
		}
	}
	verifyReplayThreads(t, f)
}

func TestThreadGroupRecoveryRepairsMismatchAfterVerifiedBlock(t *testing.T) {
	f := newReplayFixture(t, []int{2, 2, 2})
	p := f.plans[1]
	at := p.start + int64(len(p.blocks[0])) + int64(len(p.blocks[1])/2)
	original := p.file.(*os.File)
	if _, err := original.WriteAt([]byte{p.blocks[1][len(p.blocks[1])/2] ^ 0xff}, at); err != nil {
		t.Fatal(err)
	}
	file := &replayFaultFile{threadReplayFile: p.file}
	p.file = file
	if err := replayThreadGroupPlans(f.parent, f.plans); err != nil {
		t.Fatal(err)
	}
	if file.bytes != len(p.blocks[1]) || len(file.truncateAt) != 1 || file.truncateAt[0] != p.start+int64(len(p.blocks[0])) {
		t.Fatal("matching prefix discarded", file.bytes, file.truncateAt)
	}
	verifyReplayThreads(t, f)
}

func TestReplayComparisonChecksWholeLargeBlock(t *testing.T) {
	want := bytes.Repeat([]byte("large-comparison"), 12000)
	scratch := make([]byte, 64<<10)
	if same, err := equalReplayBytes(bytes.NewReader(want), 0, want, scratch); err != nil || !same {
		t.Fatal(same, err)
	}
	actual := bytes.Clone(want)
	actual[len(actual)-1] ^= 0xff
	if same, err := equalReplayBytes(bytes.NewReader(actual), 0, want, scratch); err != nil || same {
		t.Fatal("late mismatch missed", same, err)
	}
	if _, err := equalReplayBytes(bytes.NewReader(want[:len(want)-1]), 0, want, scratch); !errors.Is(err, io.EOF) {
		t.Fatal("short read hidden", err)
	}
}

func TestThreadGroupRecoveryUnreadableTailRebuilds(t *testing.T) {
	f := newReplayFixture(t, []int{2, 2, 2})
	p := f.plans[1]
	file := &replayFaultFile{threadReplayFile: p.file, readErr: syscall.EIO}
	p.file = file
	if err := replayThreadGroupPlans(f.parent, f.plans); err != nil {
		t.Fatal("authorized tail could not be rebuilt", err)
	}
	size := 0
	for _, block := range p.blocks {
		size += len(block)
	}
	if file.bytes != size || file.syncs != 1 || file.closes != 1 {
		t.Fatal("unreadable tail not rebuilt and synced", file)
	}
	verifyReplayThreads(t, f)
}

func TestThreadGroupRecoveryPreservesJoinedFailures(t *testing.T) {
	f := newReplayFixture(t, []int{0, 0, 0})
	f.plans[1].file = &replayFaultFile{threadReplayFile: f.plans[1].file, writeErr: syscall.ENOSPC}
	closeFailure := errors.New("close also failed")
	f.plans[2].file = &replayFaultFile{threadReplayFile: f.plans[2].file, closeErr: closeFailure}
	err := replayThreadGroupPlans(f.parent, f.plans)
	if !errors.Is(err, syscall.ENOSPC) || !errors.Is(err, closeFailure) {
		t.Fatal("joined failure hidden", err)
	}
	if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); err != nil {
		t.Fatal("redo lost", err)
	}
	if err := RecoverThreadCommitGroup(f.parent, f.owner, f.authorize); err != nil {
		t.Fatal("retry failed", err)
	}
	verifyReplayThreads(t, f)
}

func TestThreadGroupRecoveryRemoveFailureRemainsRetryable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission failure requires non-root")
	}
	f := newReplayFixture(t, []int{2, 2, 2})
	defer os.Chmod(f.parent, 0700)
	if err := os.Chmod(f.parent, 0500); err != nil {
		t.Fatal(err)
	}
	if err := replayThreadGroupPlans(f.parent, f.plans); !errors.Is(err, os.ErrPermission) {
		t.Fatal("remove failure hidden", err)
	}
	if _, err := os.Stat(filepath.Join(f.parent, ThreadGroupFile)); err != nil {
		t.Fatal("redo lost", err)
	}
	if err := os.Chmod(f.parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := RecoverThreadCommitGroup(f.parent, f.owner, f.authorize); err != nil {
		t.Fatal("retry failed", err)
	}
	verifyReplayThreads(t, f)
}
