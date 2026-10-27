// OWASP WSTGの入力検証・CSRF・HTTP解釈差を、隔離データと実HTTPで検査する。
package bootstrap

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestWSTGBrowser は実ブラウザで保存型XSS・DOM注入・別Originからの管理操作を検査する。
func TestWSTGBrowser(t *testing.T) {
	runAdminLayoutBrowser(t, "test-wstg-browser.mjs")
}

// TestWSTGPublicSensitivePaths は設定・保存領域・管理APIの推測URLから秘密が取得できないことを確認する。
func TestWSTGPublicSensitivePaths(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newReportTestClient(t, repo)
	defer c.server.Close()
	for _, path := range []string{
		"/.git/config", "/.git/HEAD", "/.env", "/.env.local", "/config.json", "/deploy/config.json",
		"/compose.yaml", "/Dockerfile", "/go.mod", "/keys/master-000001.key", "/data/keys/master-000001.key",
		"/instance.json", "/data/instance.json", "/reports/deletion", "/reports/http", "/cases/", "/backup.tar",
		"/debug/pprof/", "/debug/vars", "/metrics", "/api/v1/site", "/api/v1/administrators",
		"/api/v1/evidence/cases", "/login", "/admin/login", "/web/assets/../../keys/master-000001.key",
	} {
		t.Run(path, func(t *testing.T) {
			status, body := c.request("GET", path, nil)
			want := http.StatusNotFound
			if strings.Contains(path, "/../") {
				want = http.StatusBadRequest
			}
			if status != want || strings.Contains(body, adminTestSecret) || strings.Contains(body, repo.cfg.DataDir) {
				t.Fatalf("sensitive route exposed: status=%d", status)
			}
		})
	}
	status, _ := c.request("GET", "/", nil)
	if status != 200 {
		t.Fatal("ordinary public request failed", status)
	}
}

// TestWSTGAdminMutationRejectsAmbiguity は有効なセッションでも曖昧な入力を保存しないことを確認する。
func TestWSTGAdminMutationRejectsAmbiguity(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("fixture authentication")
	}
	res, original := c.site()
	csrf := res.Header.Get("X-CSRF-Token")
	session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	before := repo.site.State().Seq
	cases := []struct {
		name, body, header string
		values             []string
		status             int
	}{
		{"missing-csrf", `{"name":"unwanted"}`, "X-CSRF-Token", nil, 403},
		{"duplicate-csrf", `{"name":"unwanted"}`, "X-CSRF-Token", []string{csrf, csrf}, 403},
		{"foreign-route-csrf", `{"name":"unwanted"}`, "X-CSRF-Token", []string{session.CSRF("/api/v1/operations")}, 403},
		{"null-origin", `{"name":"unwanted"}`, "Origin", []string{"null"}, 403},
		{"foreign-origin", `{"name":"unwanted"}`, "Origin", []string{"https://attacker.invalid"}, 403},
		{"origin-prefix", `{"name":"unwanted"}`, "Origin", []string{c.origin + ".attacker.invalid"}, 403},
		{"origin-userinfo", `{"name":"unwanted"}`, "Origin", []string{strings.Replace(c.origin, "://", "://attacker@", 1)}, 403},
		{"duplicate-origin", `{"name":"unwanted"}`, "Origin", []string{c.origin, c.origin}, 403},
		{"joined-origin", `{"name":"unwanted"}`, "Origin", []string{c.origin + ", https://attacker.invalid"}, 403},
		{"cross-site", `{"name":"unwanted"}`, "Sec-Fetch-Site", []string{"cross-site"}, 403},
		{"same-site", `{"name":"unwanted"}`, "Sec-Fetch-Site", []string{"same-site"}, 403},
		{"duplicate-revision", `{"name":"unwanted"}`, "If-Match", []string{original.ETag(), original.ETag()}, 400},
		{"duplicate-request-key", `{"name":"unwanted"}`, "Idempotency-Key", []string{"wstg-duplicate-key", "wstg-duplicate-key"}, 400},
		{"duplicate-content-type", `{"name":"unwanted"}`, "Content-Type", []string{"application/json", "application/json"}, 415},
		{"mass-assignment", `{"name":"unwanted","role":"site_admin"}`, "", nil, 400},
		{"case-alias", `{"Name":"unwanted"}`, "", nil, 400},
		{"duplicate-json-key", `{"name":"first","name":"unwanted"}`, "", nil, 400},
		{"escaped-duplicate-key", `{"name":"first","\u006eame":"unwanted"}`, "", nil, 400},
		{"trailing-json", `{"name":"unwanted"}{}`, "", nil, 400},
		{"null-name", `{"name":null}`, "", nil, 400},
		{"array-name", `{"name":["unwanted"]}`, "", nil, 400},
		{"oversized-body", `{"name":"` + strings.Repeat("x", 256<<10) + `"}`, "", nil, 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}, "If-Match": {original.ETag()}, "Idempotency-Key": {"wstg-rejected-input"}}
			if tc.header != "" {
				headers[tc.header] = tc.values
			}
			response, body := c.request("PATCH", "/api/v1/site", tc.body, headers)
			if response.StatusCode != tc.status {
				t.Fatalf("got %d want %d: %s", response.StatusCode, tc.status, body)
			}
			if repo.site.State().Seq != before {
				t.Fatal("rejected input changed durable state")
			}
		})
	}
	// 成功対照で、認証不備や壊れたfixtureによる全件拒否を区別する。
	headers := http.Header{"Content-Type": {"application/json"}, "X-CSRF-Token": {csrf}, "If-Match": {original.ETag()}, "Idempotency-Key": {"wstg-valid-control"}}
	response, body := c.request("PATCH", "/api/v1/site", `{"name":"WSTG accepted control"}`, headers)
	if response.StatusCode != 200 || repo.site.State().Seq <= before {
		t.Fatalf("valid control failed: %d %s", response.StatusCode, body)
	}
}

// TestWSTGAdminRawHTTPBoundary は標準クライアントが補正する重複ヘッダーと不正framingを実socketで送る。
func TestWSTGAdminRawHTTPBoundary(t *testing.T) {
	_, repo := adminFixture(t)
	defer repo.Close()
	c := newAdminClient(t, repo)
	defer c.server.Close()
	if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
		t.Fatal("fixture authentication")
	}
	res, site := c.site()
	host := strings.TrimPrefix(c.origin, "http://")
	cookie := c.cookies["oimo_admin"].String()
	before := repo.site.State().Seq
	base := "PATCH /api/v1/site HTTP/1.1\r\nHost: " + host + "\r\nOrigin: " + c.origin + "\r\nCookie: " + cookie + "\r\nContent-Type: application/json\r\nX-CSRF-Token: " + res.Header.Get("X-CSRF-Token") + "\r\nIf-Match: " + site.ETag() + "\r\nIdempotency-Key: wstg-raw-rejection\r\nConnection: close\r\n"
	payload := `{"name":"WSTG raw control"}`
	length := fmt.Sprintf("Content-Length: %d\r\n", len(payload))
	for _, tc := range []struct {
		name, extra, body string
		status            int
	}{
		{"duplicate-host", "Host: attacker.invalid\r\n" + length, payload, 400},
		{"conflicting-length", "Content-Length: 2\r\n" + length, payload, 400},
		{"invalid-length", fmt.Sprintf("Content-Length: +%d\r\n", len(payload)), payload, 400},
		{"unsupported-transfer", "Transfer-Encoding: identity\r\n" + length, payload, 501},
		{"duplicate-transfer", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "0\r\n\r\n", 501},
		{"duplicate-origin", "Origin: " + c.origin + "\r\n" + length, payload, 403},
		{"duplicate-cookie", "Cookie: " + cookie + "\r\n" + length, payload, 401},
		{"duplicate-csrf", "X-CSRF-Token: " + res.Header.Get("X-CSRF-Token") + "\r\n" + length, payload, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, _ := wstgRawHTTP(t, c, base+tc.extra+"\r\n"+tc.body)
			if status != tc.status || repo.site.State().Seq != before {
				t.Fatalf("ambiguous request: status=%d want=%d", status, tc.status)
			}
		})
	}
	status, body := wstgRawHTTP(t, c, "GET /api/v1/site HTTP/1.1\r\nHost: "+host+"\r\nCookie: "+cookie+"\r\nConnection: close\r\n\r\n")
	if status != 200 || !strings.Contains(body, site.Name) {
		t.Fatalf("raw HTTP control failed: %d", status)
	}
	status, body = wstgRawHTTP(t, c, base+length+"\r\n"+payload)
	if status != 200 || !strings.Contains(body, "WSTG raw control") || repo.site.State().Seq <= before {
		t.Fatalf("raw mutation control failed: %d %s", status, body)
	}
}

// wstgRawHTTP は隔離サーバーだけへ接続し、応答待ちを5秒で打ち切る。
func wstgRawHTTP(t *testing.T, c *adminClient, raw string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", c.server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, raw); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(body)
}
