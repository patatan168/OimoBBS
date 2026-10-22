// 板一覧と空のスレッド一覧の導線を実際のHTTP要求で検査する。
package compatprobe

import (
	"io"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"oimobbs/internal/domain"
)

func TestBoardNavigation(t *testing.T) {
	s, err := New("http://localhost")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	s.base, _ = url.Parse(ts.URL)
	get := func(path string) string {
		t.Helper()
		res, err := ts.Client().Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("%s: status %d, %v", path, res.StatusCode, err)
		}
		return string(body)
	}
	link := regexp.MustCompile(`<a href="([^"]+)">板一覧</a>`)
	for _, path := range []string{"/oimo/", "/oimo/index.html", "/oimo/subback.html"} {
		body := get(path)
		if !strings.Contains(body, "まだスレッドがありません。") {
			t.Fatalf("%s: empty state missing", path)
		}
		match := link.FindStringSubmatch(body)
		if len(match) != 2 || match[1] != "/" {
			t.Fatalf("%s: board list link %v", path, match)
		}
		home := get(match[1])
		if !strings.Contains(home, `<a href="/oimo/">OimoBBS互換試験</a>`) {
			t.Fatal("empty board is absent from board list")
		}
	}
	// 一覧に入る板とスレッドを取り違えず、投稿後もホームの板を維持する。
	s.mu.Lock()
	s.threads[1] = &row{Key: 1, Title: "<script>thread</script>", Posts: []domain.Post{{Number: 1, Name: "tester", Body: "body"}}}
	s.mu.Unlock()
	if home := get("/"); strings.Contains(home, "thread") {
		t.Fatal("home rendered thread list")
	}
	board := get("/oimo/")
	if strings.Contains(board, "まだスレッドがありません。") || !strings.Contains(board, "&lt;script&gt;thread&lt;/script&gt;") {
		t.Fatal("thread list or escaping incorrect")
	}
	thread := get("/test/read.cgi/oimo/1/")
	if !strings.Contains(thread, `<a href="/">板一覧</a>`) || !strings.Contains(thread, `<a href="/oimo/">スレッド一覧</a>`) {
		t.Fatal("thread navigation missing")
	}
	res := httptest.NewRecorder()
	s.ServeHTTP(res, httptest.NewRequest("HEAD", ts.URL+"/", nil))
	if res.Code != 200 || res.Body.Len() != 0 {
		t.Fatal("HEAD changed")
	}
}
