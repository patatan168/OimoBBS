// 未反映本文の実byte予約を、既存の全体容量台帳へ残して二重解放と超過を拒否する。
package bootstrap

import (
	"context"
	"errors"
	"oimobbs/internal/platform"
	"oimobbs/internal/store"
	"testing"
	"time"
)

func TestPostingBodyCapacityReservation(t *testing.T) {
	_, repo, _ := postingRepositoryFixture(t)
	defer repo.Close()
	useHealthyPostingCapacity(t, repo)
	before := repo.PostingCapacity().ReservedBytes
	release, err := repo.reservePostingBodies(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	if got := repo.PostingCapacity().ReservedBytes; got != before+1<<20 {
		t.Fatal("未反映本文の容量を台帳へ残さなかった", before, got)
	}
	release()
	release()
	if got := repo.PostingCapacity().ReservedBytes; got != before {
		t.Fatal("本文容量の解放が一度でない", before, got)
	}
	repo.packResourcesMu.Lock()
	repo.packSpace = func(string) (platform.DiskSpace, error) {
		return platform.DiskSpace{Total: 2 << 30, Available: (1 << 30) + postingReservationBytes}, nil
	}
	repo.packResourcesMu.Unlock()
	if _, err := repo.reservePostingBodies(2 * postingReservationBytes); !errors.Is(err, ErrPostingCapacity) {
		t.Fatal("容量余白を超えて未反映本文を予約した", err)
	}
}

func TestPostingBodyCapacityUntilCheckpoint(t *testing.T) {
	_, repo, board := postingRepositoryFixture(t)
	defer repo.Close()
	useHealthyPostingCapacity(t, repo)
	frame := persistentFrame(t)
	created := repo.Post(context.Background(), board.ID, 0, frame, []byte(`{"fixture":true}`))
	if created.Status != store.Durable {
		t.Fatal(created)
	}
	reply := persistentReply(t, frame, time.Now())
	if result := repo.Post(context.Background(), board.ID, created.ThreadKey, reply, []byte(`{"fixture":true}`)); result.Status != store.Durable {
		t.Fatal(result)
	}
	repo.packResourcesMu.Lock()
	held, requestHeld := repo.postBodyReserved, repo.postReserved
	repo.packResourcesMu.Unlock()
	if held == 0 || requestHeld != 0 {
		t.Fatal("要求終了と本文反映の予約を区別していない", held, requestHeld)
	}
	b := repo.posting[board.ID]
	if _, err := b.worker.Submit(context.Background(), func() (any, error) { return nil, b.sharedThreadWAL.Checkpoint() }); err != nil {
		t.Fatal(err)
	}
	repo.packResourcesMu.Lock()
	held = repo.postBodyReserved
	repo.packResourcesMu.Unlock()
	if held != 0 {
		t.Fatal("checkpoint後も本文予約が残った", held)
	}
}

func TestDiskReservationsIncludePendingBodiesAndSaturate(t *testing.T) {
	r := Repository{packReserved: 1, postReserved: 2, postBodyReserved: 4, backupReserved: 8}
	r.packResourcesMu.Lock()
	defer r.packResourcesMu.Unlock()
	if got := r.reservedDiskBytes(); got != 15 {
		t.Fatal("全用途の容量予約を合算していない", got)
	}
	r.backupReserved = ^uint64(0)
	if got := r.reservedDiskBytes(); got != ^uint64(0) {
		t.Fatal("容量予約がoverflowした", got)
	}
}
