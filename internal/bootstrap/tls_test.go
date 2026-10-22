// HTTPS設定の証明書照合をローカル証明書で検証し、失敗時のdata作成を禁止する。
package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTLSCheck(t *testing.T) {
	for _, tc := range []string{"valid", "expired", "wrong_host", "wrong_key", "open_key"} {
		t.Run(tc, func(t *testing.T) {
			cfg := testConfig(t)
			cfg.Public.BaseURL = "https://localhost:9443"
			cfg.Public.Listen = "127.0.0.1:9443"
			cfg.Public.TLSCert = filepath.Join(filepath.Dir(cfg.DataDir), "tls.crt")
			cfg.Public.TLSKey = filepath.Join(filepath.Dir(cfg.DataDir), "tls.key")
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if tc == "expired" {
				cert.NotAfter = now.Add(-time.Minute)
			}
			if tc == "wrong_host" {
				cert.DNSNames = []string{"different.example"}
			}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, cfg.Public.TLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			if tc == "wrong_key" {
				_, key, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			mustWrite(t, cfg.Public.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}))
			if tc == "open_key" {
				if err = os.Chmod(cfg.Public.TLSKey, 0644); err != nil {
					t.Fatal(err)
				}
			}
			_, err = Initialize(cfg, "TLS検査")
			if tc == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err = Check(cfg); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil {
				t.Fatal("invalid TLS accepted")
			}
			if _, err = os.Stat(cfg.DataDir); !os.IsNotExist(err) {
				t.Fatal("data created before TLS validation")
			}
		})
	}
}
