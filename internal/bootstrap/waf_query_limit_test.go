// 多数クエリの早期拒否と、整理後のWAFフォームを実HTTPで検証する。
package bootstrap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"oimobbs/internal/waf"
	"os"
	"strings"
	"testing"
)

type wafQueryBody struct{ reads int }

func (b *wafQueryBody) Read([]byte) (int, error) { b.reads++; return 0, io.EOF }
func (*wafQueryBody) Close() error               { return nil }

func TestWAFQueryLimitRejectsBeforeBodyAndRoute(t *testing.T) {
	repo := &Repository{}
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	calls := 0
	handler := repo.wafHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(204) }))
	request := httptest.NewRequest("POST", "/test/bbs.cgi?"+strings.Repeat("a=1&", 128)+"a=1", nil)
	body := &wafQueryBody{}
	request.Body = body
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 403 || calls != 0 || body.reads != 0 || repo.wafBlocked.Load() != 1 || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("query reached body or route", response.Code, calls, body.reads)
	}
	if strings.Contains(response.Body.String(), "query_fields") {
		t.Fatal("internal rule exposed")
	}
	repo.publishWAF(WAFSettings{Traffic: waf.DefaultTrafficSettings()})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 204 || calls != 1 || repo.wafBlocked.Load() != 1 {
		t.Fatal("OFF behavior changed")
	}
}

func TestWAFQueryLimitRealHTTP(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	if _, err := repo.CreateBoard(t.Context(), "news", "クエリ検査"); err != nil {
		t.Fatal(err)
	}
	repo.publishWAF(WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()})
	public := wafPublicServer(t, repo)
	for _, tc := range []struct{ fields, status int }{{128, 200}, {129, 403}} {
		request, err := http.NewRequest("GET", public.URL+"/news/subject.txt?"+strings.Repeat("a=1&", tc.fields-1)+"a=1", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "127.0.0.1:9080"
		response, err := public.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != tc.status {
			t.Fatal(tc.fields, response.StatusCode)
		}
	}
}

func TestWAFManagementPageFixture(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	client := newAdminClient(t, repo)
	defer client.server.Close()
	if client.login(adminTestSecret) != 303 || client.reauth(adminTestSecret) != 200 {
		t.Fatal("login")
	}
	response, page := client.request("GET", "/waf", "", nil)
	fields := wafPageFields(page)
	if response.StatusCode != 200 || len(fields) != 23 || fields.Get("client_enabled") != "true" {
		t.Fatal("missing form fields", response.StatusCode, len(fields))
	}
	if output := os.Getenv("OIMO_WAF_PAGE_OUTPUT"); output != "" {
		if err := os.WriteFile(output, []byte(page), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
