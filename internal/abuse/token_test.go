// 匿名Cookieの設計fixtureと署名・時刻・世代境界を検証する。
package abuse

import (
	"encoding/hex"
	"oimobbs/internal/domain"
	"testing"
	"time"
)

func TestTokenVector(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	const token = "v3.7.AAECAwQFBgcICQoLDA0ODwAAAABquL7wAAAAAGrgS_AAAAAAAAAAAQAAAAAAAAAA.Jz4JD7McKEqfPyd50lRKTuAStGXgjuF0hSDT4B3LpJw"
	const old = "v1.7.AAECAwQFBgcICQoLDA0ODwAAAABquL7wAAAAAGrgS_AAAAAAAAAAAQ.avdP2DDAGlN8EzqtZ0TNLm4DtKD-RV3ZzEHaBShkAx8"
	now := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if _, err := VerifyAnon(old, key, 7, now, 1); err == nil {
		t.Fatal("old anonymous token accepted")
	}
	a, e := VerifyAnon(token, key, 7, now, 1)
	if e != nil {
		t.Fatal(e)
	}
	got, e := IssueAnon(a, key, 7)
	if e != nil || got != token {
		t.Fatal(got, e)
	}
	for _, v := range []struct {
		Token string
		Now   time.Time
		Gen   uint64
	}{{token + "=", now, 1}, {token, time.Unix(a.Expires, 0), 1}, {token, now, 2}, {token[:len(token)-1] + "A", now, 1}} {
		if _, e = VerifyAnon(v.Token, key, 7, v.Now, v.Gen); e == nil {
			t.Fatal("invalid accepted")
		}
	}
}

// TestAnonymousRecastToken は署名済みの待機期限を改変・版差替えで消せないことを検査する。
func TestAnonymousRecastToken(t *testing.T) {
	key := make([]byte, 32)
	now := time.Now().Truncate(time.Second)
	a := Anon{ID: domain.NewID(), Issued: now.Unix(), Expires: now.Unix() + 30*86400, Generation: 1, ReadyAt: now.Unix() + 1800}
	raw, err := IssueAnon(a, key, 4)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyAnon(raw, key, 4, now, 1)
	if err != nil || got != a {
		t.Fatal("recast token", got, err)
	}
	if _, err = VerifyAnon("v1"+raw[2:], key, 4, now, 1); err == nil {
		t.Fatal("version substitution accepted")
	}
	for _, ready := range []int64{a.Issued - 1, a.Issued, a.Issued + MaxAnonymousRecastSeconds + 1} {
		a.ReadyAt = ready
		if _, err = IssueAnon(a, key, 4); err == nil {
			t.Fatal("invalid recast time", ready)
		}
	}
}
func TestConfirmationBinding(t *testing.T) {
	key := make([]byte, 32)
	now := time.Unix(100000, 0)
	c := Confirmation{Board: domain.NewID(), Terms: 1, Issued: now.Unix(), Expires: now.Unix() + 600}
	token, e := IssueConfirmation(c, key, 1)
	if e != nil {
		t.Fatal(e)
	}
	if e = VerifyConfirmation(token, c, key, 1, now); e != nil {
		t.Fatal(e)
	}
	c.Request[0] = 1
	if e = VerifyConfirmation(token, c, key, 1, now); e == nil {
		t.Fatal("changed request accepted")
	}
}
