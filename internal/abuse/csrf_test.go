// Web CSRFのCookie・経路・時刻・鍵束縛と、正規表記を検証する。
package abuse

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestWebCSRFBinding(t *testing.T) {
	key := make([]byte, 32)
	cookie := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	now := time.Unix(1800000000, 0)
	token, e := IssueWebCSRF(cookie, "web_create", key, 6, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyWebCSRF(cookie, token, "web_create", key, 6, now.Add(3599*time.Second)); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		cookie, token, route string
		at                   time.Time
	}{
		{cookie, token, "web_reply", now},
		{cookie, token, "web_create", now.Add(time.Hour)},
		{cookie, token, "web_create", now.Add(-61 * time.Second)},
		{cookie + "=", token, "web_create", now},
		{cookie, token + "=", "web_create", now},
		{base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901")), token, "web_create", now},
	} {
		if VerifyWebCSRF(tc.cookie, tc.token, tc.route, key, 6, tc.at) == nil {
			t.Fatal("invalid CSRF accepted")
		}
	}
	key[0] = 1
	if VerifyWebCSRF(cookie, token, "web_create", key, 6, now) == nil {
		t.Fatal("wrong key accepted")
	}
}
