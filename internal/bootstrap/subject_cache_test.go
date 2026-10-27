// 一覧の共有生成・検証子の短縮を、旧条件と公開変更に対して検査する。
package bootstrap

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/compat"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
)

func TestCompactFeedRejectsOldConditions(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	body := []byte(strings.Repeat("feed content", 100))
	sum := sha256.Sum256(body)
	for _, suffix := range []string{"-identity", compat.GzipETagSuffix, compat.ZstdETagSuffix} {
		coding := "identity"
		if suffix == compat.GzipETagSuffix {
			coding = "gzip,identity;q=0"
		}
		if suffix == compat.ZstdETagSuffix {
			coding = "zstd,identity;q=0"
		}
		old := fmt.Sprintf(`"feed-%x%s"`, sum, suffix)
		for _, tc := range []struct {
			name, header, value string
			status              int
		}{
			{"old", "If-None-Match", old, 200},
			{"weak list", "If-None-Match", `"other", W/` + old, 200},
			{"old match", "If-Match", old, 412},
			{"weak match", "If-Match", "W/" + old, 412},
			{"obsolete", "If-None-Match", strings.Replace(old, "feed-", "feed-0", 1), 200},
			{"obsolete match", "If-Match", strings.Replace(old, "feed-", "feed-0", 1), 412},
			{"wrong profile", "If-None-Match", strings.TrimSuffix(old, suffix+`"`) + `-other"`, 200},
		} {
			t.Run(suffix+tc.name, func(t *testing.T) {
				r := httptest.NewRequest("GET", "/feed", nil)
				r.Header.Set("Accept-Encoding", coding)
				r.Header.Set(tc.header, tc.value)
				w := httptest.NewRecorder()
				repo.writeFeed(w, r, "text/plain", body, nil)
				tag := w.Header().Get("ETag")
				if w.Code != tc.status || len(old)-len(tag) != 21 || r.Header.Get(tc.header) != tc.value {
					t.Fatal(w.Code, tag, r.Header)
				}
				if tc.status == 304 && w.Body.Len() != 0 {
					t.Fatal("304 body")
				}
			})
		}
	}
}

func TestSubjectCachePublicUpdatesAndRestart(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	board, err := repo.CreateBoard(t.Context(), "subjectcache", "一覧共有")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	created, err := sendForm(form, url.Values{"bbs": {"subjectcache"}, "subject": {"TITLE<&>"}, "MESSAGE": {"first"}, "oimo_request_id": {"subject-cache-create-01"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "subject-cache-test")
	if err != nil {
		t.Fatal(err)
	}
	getPath := func(path, tag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("If-None-Match", tag)
		w := httptest.NewRecorder()
		repo.SiteWebHandler(observer).ServeHTTP(w, r)
		return w
	}
	get := func(tag string) *httptest.ResponseRecorder { return getPath("/subjectcache/subject.txt", tag) }
	htmlPath := fmt.Sprintf("/test/read.cgi/subjectcache/%d/", created.Key)
	page := getPath(htmlPath, "")
	if page.Code != 200 || page.Header().Get("ETag") != `"`+compat.FeedTag(page.Body.Bytes())+`-identity"` {
		t.Fatal("HTML validator changed", page.Code, page.Header())
	}
	htmlBuilds := repo.feedCompression.Status().Builds
	if unchanged := getPath(htmlPath, page.Header().Get("ETag")); unchanged.Code != 304 || unchanged.Body.Len() != 0 || repo.feedCompression.Status().Builds != htmlBuilds {
		t.Fatal("HTML revalidation rebuilt or sent body", unchanged.Code)
	}
	first := get("")
	if first.Code != 200 || !strings.Contains(first.Body.String(), "TITLE&lt;&amp;&gt; (1)") {
		t.Fatal(first.Code, first.Body.String())
	}
	builds := repo.feedCompression.Status().Builds
	for _, tag := range []string{"", first.Header().Get("ETag")} {
		result := get(tag)
		want := 200
		if tag != "" {
			want = 304
		}
		if result.Code != want || repo.feedCompression.Status().Builds != builds {
			t.Fatal("not shared", result.Code)
		}
	}
	reply, err := sendForm(form, url.Values{"bbs": {"subjectcache"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"reply"}, "oimo_request_id": {"subject-cache-reply-01"}})
	if err != nil || !reply.Accepted {
		t.Fatal(reply, err)
	}
	updated := get(first.Header().Get("ETag"))
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), "TITLE&lt;&amp;&gt; (2)") || updated.Header().Get("ETag") == first.Header().Get("ETag") {
		t.Fatal("stale reply", updated.Code, updated.Body.String())
	}
	updatedPage := getPath(htmlPath, page.Header().Get("ETag"))
	if updatedPage.Code != 200 || updatedPage.Header().Get("ETag") == page.Header().Get("ETag") || !strings.Contains(updatedPage.Body.String(), "reply") {
		t.Fatal("stale HTML after reply", updatedPage.Code)
	}
	admin := newAdminClient(t, repo)
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, created.Key)
	res, _ := admin.request("GET", path, "", nil)
	res, raw := admin.request("POST", path, `{"kind":"hide","ranges":[],"hide_title":false}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"subject-cache-hide-01"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, raw)
	}
	admin.server.Close()
	hidden := get(updated.Header().Get("ETag"))
	if hidden.Code != 200 || strings.Contains(hidden.Body.String(), "TITLE") {
		t.Fatal("hidden cache published", hidden.Code)
	}
	if hiddenPage := getPath(htmlPath, updatedPage.Header().Get("ETag")); hiddenPage.Code != 410 || strings.Contains(hiddenPage.Body.String(), "reply") {
		t.Fatal("cached HTML published after hide", hiddenPage.Code)
	}
	form.Close()
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	restored := get(hidden.Header().Get("ETag"))
	if restored.Code != 304 || restored.Body.Len() != 0 {
		t.Fatal("restart validator", restored.Code)
	}
}

func TestSubjectCacheKeyTracksOutput(t *testing.T) {
	rows := []publicThread{{Key: 10, Title: "first", Count: 1}, {Key: 20, Title: "second", Count: 2}}
	original := subjectCacheKey(domain.ID{1}, rows)
	for _, change := range []func([]publicThread){
		func(r []publicThread) { r[0].Key++ },
		func(r []publicThread) { r[0].Count++ },
		func(r []publicThread) { r[0].Title += "x" },
		func(r []publicThread) { r[0], r[1] = r[1], r[0] },
	} {
		next := append([]publicThread(nil), rows...)
		change(next)
		if subjectCacheKey(domain.ID{1}, next) == original {
			t.Fatal("key collision")
		}
	}
}

func TestSubjectCachedBytes(t *testing.T) {
	repo := &Repository{feedCompression: compat.NewCompressionCache(1<<20, 1)}
	r := httptest.NewRequest("GET", "/subject.txt", nil)
	for _, title := range []string{"", "<>&\"日本語😀", strings.Repeat("長い題名", 50)} {
		rows := []publicThread{{Key: 123, Title: title, Count: 45}}
		expected, err := compat.Subject([]compat.SubjectEntry{{Key: 123, Title: title, Count: 45}})
		if err != nil {
			t.Fatal(err)
		}
		for range 2 {
			actual, err := repo.subjectBody(r, domain.ID{1}, rows)
			if err != nil || !bytes.Equal(actual.Body, expected) {
				t.Fatal("changed SJIS bytes", err)
			}
		}
	}
}

func BenchmarkSubjectRepresentation(b *testing.B) {
	rows := make([]publicThread, 1000)
	for i := range rows {
		rows[i] = publicThread{Key: uint64(1800000000 + i), Title: fmt.Sprintf("一覧タイトル %d <&> %s", i, strings.Repeat("日本語のタイトル", 4)), Count: uint32(i + 1)}
	}
	request := httptest.NewRequest("GET", "/board/subject.txt", nil)
	repo := &Repository{feedCompression: compat.NewCompressionCache(16<<20, 1)}
	for _, cached := range []bool{false, true} {
		b.Run(fmt.Sprint("cached=", cached), func(b *testing.B) {
			entries := make([]compat.SubjectEntry, len(rows))
			for i, row := range rows {
				entries[i] = compat.SubjectEntry{Key: row.Key, Title: row.Title, Count: row.Count}
			}
			expected, err := compat.Subject(entries)
			if err != nil {
				b.Fatal(err)
			}
			got, err := repo.subjectBody(request, domain.ID{1}, rows)
			if err != nil || !bytes.Equal(got.Body, expected) {
				b.Fatal("different bytes", err)
			}
			b.SetBytes(int64(len(expected)))
			b.ReportAllocs()
			for b.Loop() {
				var body []byte
				var err error
				if cached {
					feed, feedErr := repo.subjectBody(request, domain.ID{1}, rows)
					body, err = feed.Body, feedErr
				} else {
					entries := make([]compat.SubjectEntry, len(rows))
					for i, row := range rows {
						entries[i] = compat.SubjectEntry{Key: row.Key, Title: row.Title, Count: row.Count}
					}
					body, err = compat.Subject(entries)
				}
				if err != nil {
					b.Fatal(err)
				}
				if len(body) == 0 {
					b.Fatal("empty")
				}
			}
		})
	}
}
