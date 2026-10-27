// Webフォームは匿名識別Cookieと別の32byte秘密に束縛し、1時間だけ使用できる。
package abuse

import (
	"crypto/hmac"
	"encoding/base64"
	"oimobbs/internal/identity"
	"strconv"
	"strings"
	"time"
)

func csrfCookie(raw string) ([]byte, error) {
	if len(raw) != 43 {
		return nil, ErrToken
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(raw)
	if e != nil || len(b) != 32 || base64.RawURLEncoding.EncodeToString(b) != raw {
		return nil, ErrToken
	}
	return b, nil
}

// IssueWebCSRF はCookie秘密・経路種別・発行秒へ用途分離HMACを付ける。
func IssueWebCSRF(cookie, route string, key []byte, keyID uint32, now time.Time) (string, error) {
	b, e := csrfCookie(cookie)
	if e != nil {
		return "", e
	}
	if len(key) != 32 || keyID == 0 || route != "web_create" && route != "web_reply" && route != "reports" || now.Unix() < 0 || now.Unix() > int64(^uint64(0)>>1)-3600 {
		return "", ErrToken
	}
	id, issued := strconv.FormatUint(uint64(keyID), 10), strconv.FormatInt(now.Unix(), 10)
	mac := identity.MAC(key, "oimo/web-csrf/v1", []byte(id), b, []byte(route), []byte(issued))
	return "v1." + id + "." + issued + "." + base64.RawURLEncoding.EncodeToString(mac[:]), nil
}

// VerifyWebCSRF は正規表記・署名・未来60秒/寿命1時間を検査する。OriginはHTTP入口で別途必須。
func VerifyWebCSRF(cookie, token, route string, key []byte, keyID uint32, now time.Time) error {
	if len(token) > 128 {
		return ErrToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "v1" || parts[1] != strconv.FormatUint(uint64(keyID), 10) {
		return ErrToken
	}
	issued, e := strconv.ParseInt(parts[2], 10, 64)
	if e != nil || issued < 0 || strconv.FormatInt(issued, 10) != parts[2] || issued > int64(^uint64(0)>>1)-3600 || now.Unix() < 0 {
		return ErrToken
	}
	if issued > now.Unix() && issued-now.Unix() > 60 || now.Unix() >= issued+3600 {
		return ErrToken
	}
	want, e := IssueWebCSRF(cookie, route, key, keyID, time.Unix(issued, 0))
	if e != nil {
		return e
	}
	if !hmac.Equal([]byte(want), []byte(token)) {
		return ErrToken
	}
	return nil
}
