// 同意署名の規約版・サイト・有効期限と、旧投稿確認の拒否を検証する。
package abuse

import (
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestConsentBindingAndExpiry(t *testing.T) {
	now := time.Unix(1800000000, 0)
	key := make([]byte, 32)
	c := Consent{Site: domain.ID{1}, Terms: 1, Issued: now.Unix(), Expires: now.Unix() + 365*86400}
	token, e := IssueConsent(c, key, 5)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyConsent(token, c, key, 5, now); e != nil {
		t.Fatal(e)
	}
	for _, modify := range []func(*Consent){func(c *Consent) { c.Site = domain.ID{2} }, func(c *Consent) { c.Terms++ }, func(c *Consent) { c.Text = domain.Hash{9} }} {
		want := c
		modify(&want)
		if VerifyConsent(token, want, key, 5, now) == nil {
			t.Fatal("binding accepted")
		}
	}
	if VerifyConsent(token, c, key, 5, time.Unix(c.Expires, 0)) == nil || VerifyConsent(token+"x", c, key, 5, now) == nil {
		t.Fatal("expired/tampered")
	}
	// 途中配備版の規約本文を持たない同意署名も受け付けない。
	prior := make([]byte, 40)
	copy(prior, c.Site[:])
	be.PutUint64(prior[16:], c.Terms)
	be.PutUint64(prior[24:], uint64(c.Issued))
	be.PutUint64(prior[32:], uint64(c.Expires))
	if VerifyConsent(sign(key, 5, "oimo/posting-consent/v1", prior), c, key, 5, now) == nil {
		t.Fatal("unbound interim consent accepted")
	}
	old, e := IssueConfirmation(Confirmation{Board: c.Site, Terms: c.Terms, Issued: now.Unix(), Expires: now.Unix() + 600}, key, 5)
	if e != nil || VerifyConsent(old, c, key, 5, now) == nil {
		t.Fatal("old content confirmation accepted", e)
	}
}
