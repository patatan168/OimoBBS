// DATの日付再取得で、同秒の複数版を取り逃さず、一意な更新秒では本文を省く。
package bootstrap

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"testing"
	"time"
)

func TestDATExactDateAcrossUpdatesAndRestart(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(context.Background(), "dates", "日付再取得")
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-20 * time.Second).Truncate(time.Second)
	clock := func(at time.Time) {
		t.Helper()
		_, err := repo.posting[board.ID].worker.Submit(context.Background(), func() (any, error) { repo.posting[board.ID].clock = func() time.Time { return at }; return nil, nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	clock(base.Add(100 * time.Millisecond))
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	created, err := sendForm(form, url.Values{"bbs": {"dates"}, "subject": {"date check"}, "MESSAGE": {"first"}, "oimo_request_id": {"date-created-0001"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "date-check")
	if err != nil {
		t.Fatal(err)
	}
	read := func(date string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", fmt.Sprintf("%s/dates/dat/%d.dat", cfg.Public.BaseURL, created.Key), nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Accept-Encoding", "identity")
		if date != "" {
			r.Header.Set("If-Modified-Since", date)
		}
		w := httptest.NewRecorder()
		repo.SiteWebHandler(observer).ServeHTTP(w, r)
		return w
	}
	check := func(status int) {
		t.Helper()
		initial := read("")
		date := initial.Header().Get("Last-Modified")
		if initial.Code != 200 || date == "" {
			t.Fatal("date absent", initial.Code)
		}
		result := read(date)
		if result.Code != status || status == 304 && result.Body.Len() != 0 {
			t.Fatal("date conditional", result.Code, status)
		}
		// 保存列から一意と判定できる日時だけ、再起動後も安全に部分再開する。
		r := httptest.NewRequest("GET", fmt.Sprintf("%s/dates/dat/%d.dat", cfg.Public.BaseURL, created.Key), nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Accept-Encoding", "identity")
		r.Header.Set("Range", fmt.Sprintf("bytes=%d-", initial.Body.Len()-1))
		r.Header.Set("If-Range", date)
		partial := httptest.NewRecorder()
		repo.SiteWebHandler(observer).ServeHTTP(partial, r)
		want := 200
		if status == 304 {
			want = 206
		}
		if partial.Code != want || want == 206 && partial.Body.String() != initial.Body.String()[initial.Body.Len()-1:] || want == 200 && partial.Body.String() != initial.Body.String() {
			t.Fatal("date resume", partial.Code, want)
		}
	}
	clock(base.Add(time.Second))
	check(304)
	for i, offset := range []time.Duration{2100 * time.Millisecond, 2500 * time.Millisecond, 4100 * time.Millisecond} {
		clock(base.Add(offset))
		reply, err := sendForm(form, url.Values{"bbs": {"dates"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"reply"}, "oimo_request_id": {fmt.Sprintf("date-reply-000000%d", i)}})
		if err != nil || !reply.Accepted {
			t.Fatal(reply, err)
		}
		clock(base.Add(offset.Truncate(time.Second) + time.Second))
		status := 304
		if i == 1 {
			status = 200
		}
		check(status)
	}
	form.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	check(304)
}
