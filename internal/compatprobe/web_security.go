// WebフォームをCookie、用途、発行時刻、同一originへ束縛する。
package compatprobe

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"oimobbs/internal/identity"
	"strconv"
	"strings"
	"time"
)

func randomToken() string { var b [32]byte; _, _ = rand.Read(b[:]); return hex.EncodeToString(b[:]) }

// sameOrigin はOriginがない通常のHTMLフォームではRefererのoriginを確認する。
func sameOrigin(r *http.Request, origin *url.URL) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	want := origin.Scheme + "://" + origin.Host
	if v := r.Header.Get("Origin"); v != "" {
		return v == want
	}
	u, e := url.Parse(r.Referer())
	return e == nil && u.User == nil && u.Scheme+"://"+u.Host == want
}
func csrfToken(key []byte, cookie, purpose string, now time.Time) string {
	issued := strconv.FormatInt(now.Unix(), 10)
	m := identity.MAC(key, "oimo/probe-csrf/v1", []byte(cookie), []byte(purpose), []byte(issued))
	return issued + "." + m.String()
}
func csrfValid(r *http.Request, token string, key []byte, cookieName, purpose string, now time.Time) bool {
	c, e := r.Cookie(cookieName)
	if e != nil || len(c.Value) != 64 {
		return false
	}
	if _, e = hex.DecodeString(c.Value); e != nil {
		return false
	}
	issued, _, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	sec, e := strconv.ParseInt(issued, 10, 64)
	if e != nil || strconv.FormatInt(sec, 10) != issued || sec > now.Unix() || sec <= now.Unix()-3600 {
		return false
	}
	return hmac.Equal([]byte(token), []byte(csrfToken(key, c.Value, purpose, time.Unix(sec, 0))))
}

// formCSRF は既存の有効なCookie値を再利用し、同時に開いたフォームを無効化しない。
func formCSRF(w http.ResponseWriter, r *http.Request, key []byte, cookieName, purpose string, secure bool, now time.Time) string {
	cookie := ""
	if c, e := r.Cookie(cookieName); e == nil && len(c.Value) == 64 {
		if _, e = hex.DecodeString(c.Value); e == nil {
			cookie = c.Value
		}
	}
	if cookie == "" {
		cookie = randomToken()
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: cookie, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: 3600})
	}
	return csrfToken(key, cookie, purpose, now)
}
