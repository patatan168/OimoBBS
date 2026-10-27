// Cookie使用と利用規約への同意を、サイトと規約版に束縛して署名する。
package abuse

import (
	"oimobbs/internal/domain"
	"time"
)

// Consent は本文やIPから独立した同意。Cookieを返す再送を同意操作として扱う。
type Consent struct {
	Site            domain.ID
	Terms           uint64
	Text            domain.Hash
	Issued, Expires int64
}

func (c Consent) valid() bool {
	return c.Site != (domain.ID{}) && c.Terms > 0 && c.Issued > 0 && c.Issued <= (1<<63-1)-365*86400 && c.Expires == c.Issued+365*86400
}

// IssueConsent は一年有効の同意Cookieを生成する。旧内容確認とは署名用途を分ける。
func IssueConsent(c Consent, key []byte, keyID uint32) (string, error) {
	if !c.valid() || len(key) != 32 || keyID == 0 {
		return "", ErrToken
	}
	p := make([]byte, 72)
	copy(p, c.Site[:])
	be.PutUint64(p[16:], c.Terms)
	copy(p[24:], c.Text[:])
	be.PutUint64(p[56:], uint64(c.Issued))
	be.PutUint64(p[64:], uint64(c.Expires))
	return sign(key, keyID, "oimo/posting-consent/v2", p), nil
}

// VerifyConsent は現行規約・サイト・時刻を検証し、旧規約や旧内容確認を拒否する。
func VerifyConsent(token string, want Consent, key []byte, keyID uint32, now time.Time) error {
	p, e := verify(token, 320, 72, key, keyID, "oimo/posting-consent/v2")
	if e != nil {
		return e
	}
	var c Consent
	copy(c.Site[:], p[:16])
	c.Terms = be.Uint64(p[16:])
	copy(c.Text[:], p[24:56])
	c.Issued = int64(be.Uint64(p[56:]))
	c.Expires = int64(be.Uint64(p[64:]))
	if !c.valid() || c.Site != want.Site || c.Terms != want.Terms || c.Text != want.Text || c.Issued > now.Unix()+60 || c.Expires <= now.Unix() {
		return ErrToken
	}
	return nil
}
