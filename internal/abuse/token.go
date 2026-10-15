// Package abuse は匿名Cookieと投稿確認Cookieの厳密な署名形式を扱う。
package abuse

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"strconv"
	"strings"
	"time"
)

var ErrToken = errors.New("invalid token")

// MaxAnonymousRecastSeconds は保存上限20万回の段階待機を符号化できる最大秒数。
const MaxAnonymousRecastSeconds int64 = (200000 - 9) * 600

var be = binary.BigEndian

// Anon は継続Cookieの認証済みpayload。公開識別とは別に扱う。
type Anon struct {
	ID              domain.ID
	Issued, Expires int64
	Generation      uint64
	ReadyAt         int64 // 再発行時の投稿待機期限。0は待機なし。
}

func sign(key []byte, keyID uint32, purpose string, payload []byte) string {
	return signVersion("v1", key, keyID, purpose, payload)
}

// signVersion は版と用途を固定したpayloadへ署名する。
func signVersion(version string, key []byte, keyID uint32, purpose string, payload []byte) string {
	id := strconv.FormatUint(uint64(keyID), 10)
	mac := identity.MAC(key, purpose, []byte(id), payload)
	return version + "." + id + "." + base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac[:])
}
func verify(token string, max, size int, key []byte, keyID uint32, purpose string) ([]byte, error) {
	return verifyVersion("v1", token, max, size, key, keyID, purpose)
}

// verifyVersion は指定版・用途・長さ・正規表現形式・MACをまとめて検査する。
func verifyVersion(version, token string, max, size int, key []byte, keyID uint32, purpose string) ([]byte, error) {
	if len(token) > max || keyID == 0 || len(key) != 32 {
		return nil, ErrToken
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != version || parts[1] != strconv.FormatUint(uint64(keyID), 10) {
		return nil, ErrToken
	}
	p, e := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if e != nil || len(p) != size || base64.RawURLEncoding.EncodeToString(p) != parts[2] {
		return nil, ErrToken
	}
	m, e := base64.RawURLEncoding.Strict().DecodeString(parts[3])
	if e != nil || len(m) != 32 || base64.RawURLEncoding.EncodeToString(m) != parts[3] {
		return nil, ErrToken
	}
	want := identity.MAC(key, purpose, []byte(parts[1]), p)
	if !hmac.Equal(want[:], m) {
		return nil, ErrToken
	}
	return p, nil
}

// IssueAnon は最大30日の継続Cookieを生成する。待機期限0も含む48byteのv3だけを出力する。
// 発行枠・投稿待機期限の永続予約は呼出元で行う。
func IssueAnon(a Anon, key []byte, keyID uint32) (string, error) {
	if len(key) != 32 || keyID == 0 || a.ID == (domain.ID{}) || a.Generation == 0 || a.Expires <= a.Issued || a.Issued > int64(^uint64(0)>>1)-30*86400 || a.Expires > a.Issued+30*86400 {
		return "", ErrToken
	}
	if a.ReadyAt != 0 && (a.ReadyAt <= a.Issued || a.ReadyAt > a.Issued+MaxAnonymousRecastSeconds) {
		return "", ErrToken
	}
	p := make([]byte, 48)
	copy(p, a.ID[:])
	be.PutUint64(p[16:], uint64(a.Issued))
	be.PutUint64(p[24:], uint64(a.Expires))
	be.PutUint64(p[32:], a.Generation)
	be.PutUint64(p[40:], uint64(a.ReadyAt))
	return signVersion("v3", key, keyID, "oimo/anon/v3", p), nil
}

// VerifyAnon は時刻・世代・MACを検証する。個別失効の判定は認証済みIDで別途行う。
func VerifyAnon(token string, key []byte, keyID uint32, now time.Time, generation uint64) (Anon, error) {
	var a Anon
	p, e := verifyVersion("v3", token, 256, 48, key, keyID, "oimo/anon/v3")
	if e != nil {
		return a, e
	}
	copy(a.ID[:], p)
	a.Issued = int64(be.Uint64(p[16:]))
	a.Expires = int64(be.Uint64(p[24:]))
	a.Generation = be.Uint64(p[32:])
	a.ReadyAt = int64(be.Uint64(p[40:]))
	if _, e = IssueAnon(a, key, keyID); e != nil || a.Generation != generation || a.Issued > now.Unix()+60 || a.Expires <= now.Unix() {
		return Anon{}, ErrToken
	}
	return a, nil
}

// Confirmation は板・規約・投稿内容・公開条件へ束縛した短期確認。
type Confirmation struct {
	Board           domain.ID
	Terms           uint64
	Request, Policy domain.Hash
	Issued, Expires int64
}

func (c Confirmation) valid() bool {
	return c.Board != (domain.ID{}) && c.Terms > 0 && c.Issued <= int64(^uint64(0)>>1)-600 && c.Expires == c.Issued+600
}

// IssueConfirmation は秘密原文を含まない104byte payloadを署名する。
func IssueConfirmation(c Confirmation, key []byte, keyID uint32) (string, error) {
	if !c.valid() || len(key) != 32 || keyID == 0 {
		return "", ErrToken
	}
	p := make([]byte, 104)
	copy(p, c.Board[:])
	be.PutUint64(p[16:], c.Terms)
	copy(p[24:], c.Request[:])
	copy(p[56:], c.Policy[:])
	be.PutUint64(p[88:], uint64(c.Issued))
	be.PutUint64(p[96:], uint64(c.Expires))
	return sign(key, keyID, "oimo/confirm/v1", p), nil
}

// VerifyConfirmation は署名と全束縛値を検査し、内容変更や満了を拒否する。
func VerifyConfirmation(token string, want Confirmation, key []byte, keyID uint32, now time.Time) error {
	p, e := verify(token, 320, 104, key, keyID, "oimo/confirm/v1")
	if e != nil {
		return e
	}
	var c Confirmation
	copy(c.Board[:], p[:16])
	c.Terms = be.Uint64(p[16:])
	copy(c.Request[:], p[24:56])
	copy(c.Policy[:], p[56:88])
	c.Issued = int64(be.Uint64(p[88:]))
	c.Expires = int64(be.Uint64(p[96:]))
	if !c.valid() || c.Board != want.Board || c.Terms != want.Terms || c.Request != want.Request || c.Policy != want.Policy || c.Expires <= now.Unix() || c.Issued > now.Unix()+60 {
		return ErrToken
	}
	return nil
}
