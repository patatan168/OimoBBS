// Admin保存から公開HTML・DAT・差分取得・再起動まで受付案内の自動更新を検査する。
package bootstrap

import (
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/postcapture"
	"oimobbs/internal/textcodec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestOperationsRefreshesPublicReportGuides(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	for _, slug := range []string{"alpha", "report"} {
		if _, err := repo.CreateBoard(t.Context(), slug, slug); err != nil {
			t.Fatal(err)
		}
	}
	repo.Close()
	cfg.AutoReports = &AutoReportConfig{"report", time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}
	var err error
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	client := newAdminClient(t, repo)
	defer func() { client.server.Close() }()
	if client.login(adminTestSecret) != 303 {
		t.Fatal("login")
	}
	public := func(path string, headers http.Header) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", cfg.Public.BaseURL+path, nil)
		request.RemoteAddr = "127.0.0.1:12345"
		request.Header = headers.Clone()
		if request.Header == nil {
			request.Header = http.Header{}
		}
		request.Header.Set("Accept-Encoding", "identity")
		recorder := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(recorder, request)
		return recorder
	}
	check := func(response *httptest.ResponseRecorder, dat bool, parts ...string) {
		t.Helper()
		body := response.Body.String()
		if dat {
			var err error
			body, err = textcodec.Decode(response.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
		}
		if response.Code != 200 {
			t.Fatal("guide HTTP", response.Code)
		}
		for _, part := range parts {
			if !strings.Contains(body, part) {
				t.Fatal("missing current guide", part)
			}
		}
	}
	previous := map[string]*httptest.ResponseRecorder{}
	for _, slug := range []string{"alpha", "report"} {
		for _, path := range []string{"/" + slug + "/dat/1.dat", "/test/read.cgi/" + slug + "/1/"} {
			response := public(path, nil)
			check(response, strings.HasSuffix(path, ".dat"), "24時間以内", "3票", "10分停止")
			previous[path] = response
		}
	}
	_, page := client.request("GET", "/operations", "", nil)
	fields := pageFields(page)
	fields.Set("maintenance_enabled", "false")
	settings := repo.operations()
	for name, value := range map[string]int{"interval_seconds": settings.Maintenance.IntervalSeconds, "max_threads": settings.Maintenance.MaxThreads, "max_seconds": settings.Maintenance.MaxSeconds, "egress_mbps": int(settings.EgressMbps())} {
		fields.Set(name, strconv.Itoa(value))
	}
	fields.Set("window_minutes", "60")
	fields.Set("quorum", "4")
	fields.Set("stop_minutes", "5")
	fields.Set("report_interval_minutes", "10")
	response, body := client.request("POST", "/operations", fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
	if response.StatusCode != 303 {
		t.Fatal("save", response.StatusCode, body)
	}
	for path, old := range previous {
		dat := strings.HasSuffix(path, ".dat")
		current := public(path, http.Header{"If-None-Match": {old.Header().Get("ETag")}})
		check(current, dat, "1時間以内", "4票", "5分停止")
		if current.Header().Get("ETag") == old.Header().Get("ETag") {
			t.Fatal("guide validator unchanged")
		}
		cached := public(path, http.Header{"If-None-Match": {current.Header().Get("ETag")}})
		if cached.Code != 304 || cached.Body.Len() != 0 {
			t.Fatal("current guide cache")
		}
		if dat {
			for _, headers := range []http.Header{
				{"Range": {"bytes=" + strconv.Itoa(old.Body.Len()) + "-"}},
				{"Range": {"bytes=1-"}, "If-Range": {old.Header().Get("ETag")}},
			} {
				reloaded := public(path, headers)
				check(reloaded, true, "1時間以内", "4票", "5分停止")
				if reloaded.Body.String() != current.Body.String() {
					t.Fatal("guide returned a partial replacement")
				}
			}
			valid := public(path, http.Header{"Range": {"bytes=1-"}, "If-Range": {current.Header().Get("ETag")}})
			if valid.Code != 206 || valid.Body.String() != current.Body.String()[1:] {
				t.Fatal("validated same-version range")
			}
		}
	}
	client.server.Close()
	repo.Close()
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	for path := range previous {
		check(public(path, nil), strings.HasSuffix(path, ".dat"), "1時間以内", "4票", "5分停止")
	}
}
