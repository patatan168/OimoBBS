// 投稿列が保存待ちでも確定済みDATと閲覧HTMLを取得できることを検査する。
package bootstrap

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

func TestLiveReadsDoNotWaitForPostingWorker(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(context.Background(), "live", "実況")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"live"}, "subject": {"title"}, "MESSAGE": {"body"}, "oimo_request_id": {"live-create-0001"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "live-test")
	if err != nil {
		t.Fatal(err)
	}
	handler := repo.SiteWebHandler(observer)
	owner, err := repo.postingOwner(board.ID)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = owner.worker.Submit(context.Background(), func() (any, error) {
			close(entered)
			<-release
			return nil, nil
		})
	}()
	<-entered
	defer func() { close(release); <-finished }()
	for _, path := range []string{fmt.Sprintf("/live/dat/%d.dat", created.Key), fmt.Sprintf("/test/read.cgi/live/%d/", created.Key)} {
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() {
			request := httptest.NewRequest("GET", repo.cfg.Public.BaseURL+path, nil)
			request.RemoteAddr = "127.0.0.1:12345"
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			result <- response
		}()
		select {
		case response := <-result:
			if response.Code != 200 || response.Body.Len() == 0 {
				t.Fatal(path, response.Code)
			}
		case <-time.After(time.Second):
			t.Fatal("committed read waited for posting worker", path)
		}
	}
}
