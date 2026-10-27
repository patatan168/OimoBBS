// 一覧読取りが投稿の耐久保存待ちと分離され、確定済み世代だけを返すことを検査する。
package bootstrap

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestThreadListingDoesNotWaitForPostingOwner(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "listingreader", "一覧分離")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	posted, err := sendForm(form, url.Values{"bbs": {"listingreader"}, "subject": {"確定した一覧"}, "MESSAGE": {"first"}, "oimo_request_id": {"listing-reader-create-01"}})
	if err != nil || !posted.Accepted {
		t.Fatal(posted, err)
	}
	b, err := repo.postingOwner(board.ID)
	if err != nil {
		t.Fatal(err)
	}
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = b.worker.Submit(context.Background(), func() (any, error) { close(started); <-release; return nil, nil })
	}()
	<-started
	defer func() { close(release); <-done }()
	fetched := make(chan error, 1)
	go func() {
		rows, _, err := repo.threadListings(httptest.NewRequest("GET", "/listingreader/subject.txt", nil), board.ID)
		if err == nil && (len(rows) != 1 || rows[0].Key != posted.Key || rows[0].Count != 1) {
			fetched <- ErrPostingUnavailable
			return
		}
		fetched <- err
	}()
	select {
	case err := <-fetched:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("listing waited for posting owner")
	}
}
