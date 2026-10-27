// 圧縮済みDATが残っていても、非公開変更後の再取得・304応答を拒否する。
package bootstrap

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/compat"
	"strings"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
)

func TestCachedDATRespectsHide(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(context.Background(), "cached", "共有配信")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"cached"}, "subject": {"title"}, "MESSAGE": {"body"}, "oimo_request_id": {"cached-create-0001"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "cache-test")
	if err != nil {
		t.Fatal(err)
	}
	handler := repo.SiteWebHandler(observer)
	get := func(coding, tag string) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", fmt.Sprintf("%s/cached/dat/%d.dat", repo.cfg.Public.BaseURL, created.Key), nil)
		request.RemoteAddr = "127.0.0.1:12345"
		request.Header.Set("Accept-Encoding", coding+", identity;q=0")
		if tag != "" {
			request.Header.Set("If-None-Match", tag)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, request)
		return w
	}
	tags := map[string]string{}
	for _, coding := range []string{"gzip", "zstd"} {
		first := get(coding, "")
		if first.Code != 200 || first.Header().Get("Content-Encoding") != coding {
			t.Fatal("cache warmup", first.Code)
		}
		tags[coding] = first.Header().Get("ETag")
		builds := repo.feedCompression.Status().Builds
		if again := get(coding, ""); again.Code != 200 || repo.feedCompression.Status().Builds != builds {
			t.Fatal("cache not shared", again.Code)
		}
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, created.Key)
	response, _ := admin.request("GET", path, "", nil)
	response, body := admin.request("POST", path, `{"kind":"hide","ranges":[],"hide_title":false}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {response.Header.Get("ETag")}, "X-CSRF-Token": {response.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"cached-hide-00001"}})
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode, body)
	}
	for coding, tag := range tags {
		for _, validator := range []string{"", tag} {
			if result := get(coding, validator); result.Code != 410 {
				t.Fatal("cached hidden DAT published", coding, result.Code)
			}
		}
	}
}

// TestCachedHTMLCurrentVersion は共有HTMLでも追加投稿と非公開変更を直ちに反映する。
func TestCachedHTMLCurrentVersion(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	board, err := repo.CreateBoard(t.Context(), "htmlcache", "HTML共有")
	if err != nil {
		t.Fatal(err)
	}
	form := formServer(t, repo, siteID(repo.site.State()), board.ID)
	defer form.Close()
	created, err := sendForm(form, url.Values{"bbs": {"htmlcache"}, "subject": {"title"}, "MESSAGE": {"FIRST-PUBLIC-BODY"}, "oimo_request_id": {"html-cache-create-0001"}})
	if err != nil || !created.Accepted {
		t.Fatal(created, err)
	}
	observer, err := evidence.NewHTTPObserver(siteID(repo.site.State()), domain.NewID(), "html-cache-test")
	if err != nil {
		t.Fatal(err)
	}
	handler := repo.SiteWebHandler(observer)
	get := func(method, tag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, fmt.Sprintf("%s/test/read.cgi/htmlcache/%d/", repo.cfg.Public.BaseURL, created.Key), nil)
		r.RemoteAddr = "127.0.0.1:12345"
		if tag != "" {
			r.Header.Set("If-None-Match", tag)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	first := get("GET", "")
	if first.Code != 200 || !strings.Contains(first.Body.String(), "FIRST-PUBLIC-BODY") {
		t.Fatal("first HTML", first.Code)
	}
	builds := repo.feedCompression.Status().Builds
	if second := get("GET", ""); second.Code != 200 || second.Body.String() != first.Body.String() || repo.feedCompression.Status().Builds != builds {
		t.Fatal("HTML not shared")
	}
	if conditional := get("GET", first.Header().Get("ETag")); conditional.Code != 304 || conditional.Body.Len() != 0 || repo.feedCompression.Status().Builds != builds {
		t.Fatal("HTML validator")
	}
	if head := get("HEAD", ""); head.Code != 200 || head.Body.Len() != 0 || repo.feedCompression.Status().Builds != builds {
		t.Fatal("HTML HEAD")
	}
	replied, err := sendForm(form, url.Values{"bbs": {"htmlcache"}, "key": {fmt.Sprint(created.Key)}, "MESSAGE": {"SECOND-PUBLIC-BODY"}, "oimo_request_id": {"html-cache-reply-0001"}})
	if err != nil || !replied.Accepted {
		t.Fatal(replied, err)
	}
	getGzip := func(tag string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", fmt.Sprintf("%s/test/read.cgi/htmlcache/%d/", repo.cfg.Public.BaseURL, created.Key), nil)
		r.RemoteAddr = "127.0.0.1:12345"
		r.Header.Set("Accept-Encoding", "gzip,identity;q=0")
		r.Header.Set("If-None-Match", tag)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	compressed := getGzip("")
	if compressed.Code != 200 || !strings.Contains(compressed.Header().Get("ETag"), compat.GzipLiveETagSuffix) {
		t.Fatal("live HTML gzip", compressed.Code, compressed.Header())
	}
	reader, err := gzip.NewReader(bytes.NewReader(compressed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !strings.Contains(string(decoded), "SECOND-PUBLIC-BODY") {
		t.Fatal("live HTML content", err)
	}
	buildCount := repo.feedCompression.Status().Builds
	if checked := getGzip(compressed.Header().Get("ETag")); checked.Code != 304 || checked.Body.Len() != 0 || repo.feedCompression.Status().Builds != buildCount {
		t.Fatal("live HTML conditional cache")
	}
	updated := get("GET", first.Header().Get("ETag"))
	if updated.Code != 200 || !strings.Contains(updated.Body.String(), "SECOND-PUBLIC-BODY") || updated.Header().Get("ETag") == first.Header().Get("ETag") {
		t.Fatal("stale HTML after post", updated.Code)
	}
	admin := newAdminClient(t, repo)
	defer admin.server.Close()
	if admin.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	path := fmt.Sprintf("/api/v1/boards/%s/threads/%d/moderation", board.ID, created.Key)
	res, _ := admin.request("GET", path, "", nil)
	res, body := admin.request("POST", path, `{"kind":"hide","ranges":[],"hide_title":false}`, http.Header{"Content-Type": {"application/json"}, "If-Match": {res.Header.Get("ETag")}, "X-CSRF-Token": {res.Header.Get("X-CSRF-Token")}, "Idempotency-Key": {"html-cache-hide-0001"}})
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode, body)
	}
	if hidden := getGzip(compressed.Header().Get("ETag")); hidden.Code != 410 {
		t.Fatal("hidden live gzip", hidden.Code)
	}
	for _, tag := range []string{"", updated.Header().Get("ETag")} {
		if hidden := get("GET", tag); hidden.Code != 410 || strings.Contains(hidden.Body.String(), "FIRST-PUBLIC-BODY") {
			t.Fatal("hidden cached HTML", hidden.Code)
		}
	}
}
