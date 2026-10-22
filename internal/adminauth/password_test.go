// Argon2idの固定構成・旧方式拒否・保存値からの過大な計算指定の拒否を検証する。
package adminauth

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"oimobbs/internal/strictjson"
)

func TestArgon2idReferenceVector(t *testing.T) {
	// 固定パラメータは保存値の検査を通ってからだけ計算へ渡す。
	p, err := NewPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if p.Algorithm != "argon2id" || p.Version != 19 || p.Memory != 65536 || p.Iterations != 3 || p.Parallelism != 4 {
		t.Fatal("unexpected parameters")
	}
	for name, edit := range map[string]func(*Password){
		"legacy":      func(p *Password) { p.Algorithm = "pbkdf2-sha256"; p.Iterations = 600000 },
		"version":     func(p *Password) { p.Version = 16 },
		"memory":      func(p *Password) { p.Memory = ^uint32(0) },
		"time":        func(p *Password) { p.Iterations = ^uint32(0) },
		"parallelism": func(p *Password) { p.Parallelism = 255 },
		"salt":        func(p *Password) { p.Salt = "AA==" },
		"digest":      func(p *Password) { p.Digest = "AA==" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := p
			edit(&bad)
			if bad.Validate() == nil || bad.Verify(testPassword) {
				t.Fatal("invalid credential accepted")
			}
		})
	}
	// libargon2 argon2id_hash_raw(3,65536,4)で独立生成した期待値。
	digest, err := hex.DecodeString("d6f1ccd271649908cedf0397452427b0a7c345c1485ca3d83d3fb5b0f4f819e4")
	if err != nil {
		t.Fatal(err)
	}
	p.Salt = base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	p.Digest = base64.StdEncoding.EncodeToString(digest)
	if !p.Verify(testPassword) {
		t.Fatal("reference vector mismatch")
	}
}

func TestPasswordStorageRejectsLegacyAndMalformedFields(t *testing.T) {
	for _, raw := range []string{
		`{"algorithm":"pbkdf2-sha256","iterations":600000,"salt_base64":"MDEyMzQ1Njc4OWFiY2RlZg==","digest_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"algorithm":"argon2id","version":19,"iterations":3,"memory_kib":65536,"parallelism":4,"salt_base64":"MDEyMzQ1Njc4OWFiY2RlZg==","digest_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","unknown":1}`,
		`{"algorithm":"argon2id","version":19,"iterations":3,"memory_kib":65536,"memory_kib":1,"parallelism":4,"salt_base64":"MDEyMzQ1Njc4OWFiY2RlZg==","digest_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"algorithm":"argon2id","version":19,"iterations":3,"memory_kib":null,"parallelism":4,"salt_base64":"MDEyMzQ1Njc4OWFiY2RlZg==","digest_base64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
	} {
		var p Password
		if strictjson.Decode([]byte(raw), &p) == nil {
			t.Fatal("invalid password storage accepted")
		}
	}
}

func TestPasswordWorkLimits(t *testing.T) {
	m, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for range cap(m.workers) {
		m.workers <- struct{}{}
	}
	if _, err = m.DerivePassword(testPassword); err != ErrBusy {
		t.Fatal("creation bypassed worker limit", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = m.Verify(ctx, nil, testPassword); err != context.Canceled {
		t.Fatal("queued verification ignored cancellation", err)
	}
	if len(m.slots) != 0 {
		t.Fatal("canceled verification leaked slot")
	}
	for range cap(m.slots) {
		m.slots <- struct{}{}
	}
	if _, err = m.Verify(context.Background(), nil, testPassword); err != ErrBusy {
		t.Fatal("verification bypassed queue limit", err)
	}
}
