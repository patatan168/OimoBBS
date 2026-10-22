// 入口専用証明書の用途・再生成拒否と、CA秘密鍵の非保存を検査する。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDedicatedEdgeIdentity(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	if err := initializeClient(dir); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "ca.pem"))
	block, _ := pem.Decode(raw)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client identity accepted as server")
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 3 {
		t.Fatal("unexpected persisted key material")
	}
	if err = initializeClient(dir); err == nil {
		t.Fatal("identity silently replaced")
	}
}
