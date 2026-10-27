// 保存列から公開した一覧停止状態と、取消済み要求の拒否を確認する。
package bootstrap

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
)

func TestThreadListingStoppedAndCanceled(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "listingstate", "一覧の停止")
	if err != nil {
		t.Fatal(err)
	}
	b, err := repo.postingOwner(board.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.worker.Submit(t.Context(), func() (any, error) { b.stopped = true; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/listingstate/subject.txt", nil)
	if _, _, err = repo.threadListings(request, board.ID); !errors.Is(err, ErrPostingUnavailable) {
		t.Fatal("stopped board listed", err)
	}
	if _, err = b.worker.Submit(t.Context(), func() (any, error) { b.stopped = false; return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if _, _, err = repo.threadListings(request, board.ID); err != nil {
		t.Fatal("resumed board not listed", err)
	}
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	if _, _, err = repo.threadListings(request.WithContext(ctx), board.ID); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled request listed", err)
	}
}
