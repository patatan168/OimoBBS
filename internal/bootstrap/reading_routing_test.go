// 読取り共有ロック中にも板の追加と停止を安全に反映できることを検査する。
package bootstrap

import (
	"fmt"
	"sync"
	"testing"
)

func TestPublicMetadataConcurrentUpdates(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "original", "元の板")
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var readers sync.WaitGroup
	for range 8 {
		readers.Go(func() {
			<-start
			for range 128 {
				got, err := repo.webBoard("original")
				if err != nil || got == nil || got.ID != board.ID {
					t.Error("board changed", got, err)
					return
				}
				if _, err := repo.postingOwner(board.ID); err != nil {
					t.Error(err)
					return
				}
				_ = repo.protectedBoardSlugs()
			}
		})
	}
	close(start)
	for i := range 3 {
		if _, err := repo.CreateBoard(t.Context(), fmt.Sprintf("added%d", i), "追加の板"); err != nil {
			t.Error(err)
		}
	}
	readers.Wait()
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.webBoard("original"); err == nil {
		t.Fatal("closed repository remained readable")
	}
	if _, err := repo.postingOwner(board.ID); err == nil {
		t.Fatal("closed owner remained available")
	}
}
