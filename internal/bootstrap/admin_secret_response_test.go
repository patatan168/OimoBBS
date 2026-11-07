// 登録用・再発行した秘密を、送信中に失効した管理セッションへ渡さないことを検証する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/domain"
)

// TestAdminSecretResponseRechecksSession は実ハンドラーのヘッダー確定時にログアウトし、秘密本文の中断を検査する。
func TestAdminSecretResponseRechecksSession(t *testing.T) {
	for _, kind := range []string{"otp-begin", "otp-qr", "cap-create", "cap-reset", "cap-update", "password-reset"} {
		formats := []bool{true, false}
		if strings.HasPrefix(kind, "otp-") {
			formats = []bool{true}
		}
		for _, api := range formats {
			name := kind + "/html"
			if api {
				name = kind + "/api"
			}
			t.Run(name, func(t *testing.T) {
				_, repo := adminFixture(t)
				defer repo.Close()
				repo.cfg.Admin.Origin = "http://localhost:9081"
				c := newAdminClient(t, repo)
				defer c.server.Close()
				if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
					t.Fatal("fixture authentication")
				}
				request := secretResponseRequest(t, repo, c, kind, api)
				control := httptest.NewRecorder()
				c.server.Config.Handler.ServeHTTP(control, request())
				assertSecretResponse(t, control, kind, api)
				req := request()
				cookie := c.cookies["oimo_admin"].Value
				recorder := httptest.NewRecorder()
				invalidated := false
				writer := &logoutReportWriter{recorder, func() {
					invalidated = true
					repo.adminAuth.Delete(cookie)
				}}
				func() {
					defer func() {
						if got := recover(); got != http.ErrAbortHandler {
							t.Errorf("secret send was not aborted after logout: %v", got)
						}
					}()
					c.server.Config.Handler.ServeHTTP(writer, req)
				}()
				if !invalidated || recorder.Body.Len() != 0 {
					t.Errorf("secret response escaped logout: invalidated=%v bytes=%d", invalidated, recorder.Body.Len())
				}
			})
		}
	}
}

// secretResponseRequest は正常なCSRF・版・再送キーを持つ要求を毎回組み立て、失効だけを攻撃条件にする。
func secretResponseRequest(t *testing.T, repo *Repository, c *adminClient, kind string, api bool) func() *http.Request {
	t.Helper()
	var board, account domain.ID
	if strings.HasPrefix(kind, "cap-") {
		created, err := repo.CreateBoard(t.Context(), "secretresponse", "秘密応答検査")
		if err != nil {
			t.Fatal(err)
		}
		board = created.ID
	}
	if kind == "password-reset" {
		account = createRecoveryAccount(t, c, "moderator").ID
	}
	if kind == "otp-qr" {
		res, _ := otpPost(c, "register/begin", struct{}{})
		if res.StatusCode != 200 {
			t.Fatal("OTP enrollment setup", res.StatusCode)
		}
	}
	return func() *http.Request {
		t.Helper()
		session, err := repo.adminAuth.Lookup(c.cookies["oimo_admin"].Value, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		method, route, body, etag := "POST", "", "{}", ""
		var input any = struct{}{}
		switch kind {
		case "otp-begin":
			route = otpRoute + "register/begin"
		case "otp-qr":
			method, route = "GET", otpRoute+"register/qr"
		case "password-reset":
			detail, _ := c.request("GET", "/api/v1/administrators/"+account.String(), "", nil)
			etag = detail.Header.Get("ETag")
			route = "/api/v1/administrators/" + account.String() + "/password-reset"
		default:
			route = "/api/v1/caps"
			if kind != "cap-create" {
				cap, _ := createTestCap(t, repo, c, board, []string{"post"})
				route += "/" + cap.ID.String() + "/" + strings.TrimPrefix(kind, "cap-")
				etag = cap.ETag()
			} else {
				list, _ := c.request("GET", route, "", nil)
				etag = list.Header.Get("ETag")
			}
			if kind != "cap-reset" {
				input = capInput{Name: "応答検査", Boards: []domain.ID{board}, Permissions: []string{"post"}}
			}
		}
		csrfRoute := route
		if strings.HasPrefix(kind, "otp-") {
			csrfRoute = otpRoute
		}
		headers := http.Header{}
		if api {
			raw, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			body = string(raw)
			headers.Set("Content-Type", "application/json")
			headers.Set("X-CSRF-Token", session.CSRF(csrfRoute))
			headers.Set("If-Match", etag)
			headers.Set("Idempotency-Key", domain.NewID().String())
		} else {
			form := url.Values{"csrf": {session.CSRF(csrfRoute)}, "revision": {etag}, "request_id": {domain.NewID().String()}}
			if cap, ok := input.(capInput); ok {
				form.Set("display_name", cap.Name)
				form.Set("board_ids", board.String())
				form.Set("permissions", "post")
				form.Set("expires_at", "")
			}
			body = form.Encode()
			headers.Set("Content-Type", "application/x-www-form-urlencoded")
			route = strings.TrimPrefix(route, "/api/v1")
		}
		req := webReadTestRequest(method, c.origin+route, strings.NewReader(body))
		req.RemoteAddr = "127.0.0.1:12345"
		for key, values := range headers {
			req.Header[key] = values
		}
		req.Header.Set("Origin", c.origin)
		for _, cookie := range c.cookies {
			req.AddCookie(cookie)
		}
		return req
	}
}

// assertSecretResponse は失効なしの対照応答に実際の秘密またはQRがあることを確認し、値はログへ出さない。
func assertSecretResponse(t *testing.T, res *httptest.ResponseRecorder, kind string, api bool) {
	t.Helper()
	if res.Code != 200 {
		t.Fatal("control response", res.Code)
	}
	if kind == "otp-qr" {
		if _, err := png.Decode(bytes.NewReader(res.Body.Bytes())); err != nil {
			t.Fatal("control QR", err)
		}
		return
	}
	if api {
		var data struct {
			Secret    string `json:"secret"`
			Temporary string `json:"temporary_password"`
		}
		if json.Unmarshal(res.Body.Bytes(), &data) != nil || len(data.Secret)+len(data.Temporary) < 32 {
			t.Fatal("control response contains no secret")
		}
		return
	}
	marker := "#cap:"
	if kind == "password-reset" {
		marker = "data-temporary-password>"
	}
	if !strings.Contains(res.Body.String(), marker) {
		t.Fatal("control page contains no secret")
	}
}
