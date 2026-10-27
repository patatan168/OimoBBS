// 板一覧のメタデータ参照が、他のサイト読取りを排他しないことを確認する。
package bootstrap

import (
	"testing"
	"time"
)

func TestWebBoardsDoesNotWaitForOtherReaders(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	repo.mu.RLock()
	done := make(chan error, 1)
	go func() { _, _, err := repo.webBoards(); done <- err }()
	select {
	case err := <-done:
		repo.mu.RUnlock()
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		repo.mu.RUnlock()
		<-done
		t.Fatal("板一覧がサイトの書込みロックを要求した")
	}
}
