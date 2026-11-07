// 秘密応答の帯域待機中に変わった登録状態と、実HTTP接続の中断を検証する。
package bootstrap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestAdminOTPSecretResponseRechecksEnrollment は秘密とQRの送信待機中の登録消費・期限切れ・設定更新を検査する。
func TestAdminOTPSecretResponseRechecksEnrollment(t *testing.T) {
	for _, qr := range []bool{false, true} {
		for _, headers := range []bool{false, true} {
			for _, change := range []string{"consumed", "expired", "security-changed"} {
				name := "secret/body/" + change
				if qr {
					name = "qr/body/" + change
				}
				if headers {
					name = strings.Replace(name, "/body/", "/headers/", 1)
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
					h := &adminHandler{repo: repo, auth: repo.adminAuth, origin: c.origin}
					makeBegin := secretResponseRequest(t, repo, c, "otp-begin", true)
					req := makeBegin()
					token := ""
					if qr {
						setup := httptest.NewRecorder()
						h.ServeHTTP(setup, req)
						assertSecretResponse(t, setup, "otp-begin", true)
						for _, cookie := range setup.Result().Cookies() {
							if cookie.Name == "oimo_admin_otp" {
								token = cookie.Value
								req.AddCookie(cookie)
							}
						}
						req.Method, req.URL.Path, req.Body = "GET", otpRoute+"register/qr", nil
						req.Header.Set("Accept-Encoding", "gzip;q=0.1")
					}
					recorder := httptest.NewRecorder()
					changed := false
					invalidate := func() {
						changed = true
						if !repo.mu.TryLock() {
							t.Fatal("OTP response waits while holding the site mutex")
						}
						defer repo.mu.Unlock()
						if !qr {
							response := &http.Response{Header: recorder.Header()}
							for _, cookie := range response.Cookies() {
								if cookie.Name == "oimo_admin_otp" {
									token = cookie.Value
								}
							}
						}
						invalidateOTPResponse(t, h, c.cookies["oimo_admin"].Value, token, change)
					}
					writer := &evidenceResponseWait{ResponseRecorder: recorder}
					if headers {
						writer.onHeaders = invalidate
					} else {
						writer.onBody = invalidate
					}
					func() {
						defer func() {
							if got := recover(); got != http.ErrAbortHandler {
								t.Errorf("obsolete OTP secret send was not aborted: %v", got)
							}
						}()
						h.ServeHTTP(writer, req)
					}()
					if !changed || recorder.Body.Len() != 0 {
						t.Fatal("OTP response escaped enrollment change", changed, recorder.Body.Len())
					}
				})
			}
		}
	}
}

// invalidateOTPResponse は共通mutex内で登録だけを変え、セッション失効以外の拒否理由を再現する。
func invalidateOTPResponse(t *testing.T, h *adminHandler, binding, token, change string) {
	t.Helper()
	pending, ok := h.otp.peek(token, binding, time.Now())
	if !ok {
		t.Fatal("response enrollment missing")
	}
	clear(pending.Secret)
	switch change {
	case "consumed":
		pending, ok := h.otp.take(token, binding, time.Now())
		if !ok {
			t.Fatal("cannot consume enrollment")
		}
		clear(pending.Secret)
	case "expired":
		h.otp.mu.Lock()
		h.otp.pending[token].Expires = time.Now().Add(-time.Second)
		h.otp.mu.Unlock()
	case "security-changed":
		session, err := h.auth.Lookup(binding, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a, err := h.repo.currentAdminSession(session)
		if err != nil {
			t.Fatal(err)
		}
		state, _, err := h.repo.adminSecurityLocked(a)
		if err == nil {
			err = h.repo.saveAdminSecurityLocked(a, state, "administrator_otp_test", false)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// secretLogoutHTTPWriter は実socketのヘッダーをflushしてからログアウトし、標準サーバーの本文中断を試す。
type secretLogoutHTTPWriter struct {
	http.ResponseWriter
	logout func()
}

func (w *secretLogoutHTTPWriter) WriteHeader(status int) {
	w.ResponseWriter.WriteHeader(status)
	w.ResponseWriter.(http.Flusher).Flush()
	w.logout()
}

// TestAdminSecretResponseAbortsHTTP は実HTTPで成功ヘッダー後に秘密本文が送られず、不完全応答として終了することを検査する。
func TestAdminSecretResponseAbortsHTTP(t *testing.T) {
	for _, kind := range []string{"otp-begin", "cap-create", "password-reset"} {
		t.Run(kind, func(t *testing.T) {
			_, repo := adminFixture(t)
			defer repo.Close()
			repo.cfg.Admin.Origin = "http://localhost:9081"
			c := newAdminClient(t, repo)
			defer c.server.Close()
			if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
				t.Fatal("fixture authentication")
			}
			makeRequest := secretResponseRequest(t, repo, c, kind, true)
			control := httptest.NewRecorder()
			c.server.Config.Handler.ServeHTTP(control, makeRequest())
			assertSecretResponse(t, control, kind, true)
			req := makeRequest()
			cookie := c.cookies["oimo_admin"].Value
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.server.Config.Handler.ServeHTTP(&secretLogoutHTTPWriter{w, func() { repo.adminAuth.Delete(cookie) }}, r)
			}))
			defer server.Close()
			server.Client().Timeout = 5 * time.Second
			req.URL, _ = url.Parse(server.URL + req.URL.RequestURI())
			req.RequestURI = ""
			res, err := server.Client().Do(req)
			if err != nil {
				t.Fatal("response headers", err)
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if res.StatusCode != 200 || err == nil || len(body) != 0 {
				t.Fatalf("revoked secret HTTP response: status=%d bytes=%d read_error=%v", res.StatusCode, len(body), err)
			}
		})
	}
}
