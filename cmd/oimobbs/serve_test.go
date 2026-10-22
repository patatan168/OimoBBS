// 本番起動のHTTPS/管理分離・準備拒否・再起動・hot reloadと30秒終了境界を確認する。
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func publicFixture(t *testing.T) (bootstrap.Config, *http.Client, func(int64)) {
	t.Helper()
	address := func() string {
		socket, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		return socket.Addr().String()
	}
	public, admin := address(), address()
	root := t.TempDir()
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(root, "site"), Public: bootstrap.PublicConfig{Listen: public, BaseURL: "https://" + public, TLSCert: filepath.Join(root, "cert.pem"), TLSKey: filepath.Join(root, "key.pem")}, Admin: bootstrap.AdminConfig{Listen: admin, Origin: "http://" + admin, Transport: "loopback_tunnel"}, TrustedProxies: []string{}, EgressBits: 80000000}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "public test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Public.TLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.Public.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true}}
	t.Cleanup(func() { client.CloseIdleConnections() })
	parent, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	rotate := func(serial int64) {
		t.Helper()
		leafPub, leafKey, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "public rotated"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		leafDER, e := x509.CreateCertificate(rand.Reader, leaf, parent, leafPub, key)
		if e != nil {
			t.Fatal(e)
		}
		leafEncoded, e := x509.MarshalPKCS8PrivateKey(leafKey)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(cfg.Public.TLSCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(cfg.Public.TLSKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafEncoded}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	return cfg, client, rotate
}

func TestPublicServeLifecycle(t *testing.T) {
	cfg, client, rotate := publicFixture(t)
	if _, err := bootstrap.Initialize(cfg, "公開試験"); err != nil {
		t.Fatal(err)
	}
	// 不足した規制は暗黙で有効化せず、Listen前に拒否する。
	if err := serveConfiguredWithNetworkClient(t.Context(), cfg, false, "", "", "", io.Discard, true, nil, true, offlineNetworkClient()); err == nil {
		t.Fatal("unmetered startup")
	}
	r, err := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { r.Close() }()
	if _, err = r.ConfigureAdministrator("owner", "所有者", "public-test-secret-0001", false); err != nil {
		t.Fatal(err)
	}
	r.Close()
	r, err = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.CreateBoard(t.Context(), "news", "公開板"); err != nil {
		t.Fatal(err)
	}

	if _, err = r.EnableAdmission(); err != nil {
		t.Fatal(err)
	}
	r.Close()
	for range 2 {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- serveConfiguredWithNetworkClient(ctx, cfg, false, "", "", "", io.Discard, true, nil, true, offlineNetworkClient())
		}()
		ready := false
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			res, e := client.Get(cfg.Public.BaseURL + "/bbsmenu.json")
			if e == nil {
				res.Body.Close()
				if res.StatusCode == 200 && res.Header.Get("X-Oimo-Environment") == "production" {
					if res.ProtoMajor != 2 {
						cancel()
						t.Fatal("HTTP/2 absent")
					}
					ready = true
					break
				}
			}
			select {
			case e := <-done:
				cancel()
				t.Fatal("public startup", e)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			cancel()
			t.Fatal("not ready")
		}
		rotate(2)
		client.CloseIdleConnections()
		rotated, e := client.Get(cfg.Public.BaseURL + "/bbsmenu.json")
		if e != nil {
			cancel()
			t.Fatal("certificate reload", e)
		}
		rotated.Body.Close()
		if rotated.TLS.PeerCertificates[0].SerialNumber.Int64() != 2 {
			cancel()
			t.Fatal("old certificate")
		}
		res, e := http.Get(cfg.Admin.Origin + "/login")
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != 200 {
			cancel()
			t.Fatal("admin listener")
		}
		res, e = client.Get(cfg.Public.BaseURL + "/api/v1/site")
		if e != nil {
			cancel()
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode == 200 {
			cancel()
			t.Fatal("admin on public")
		}
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("shutdown")
		}
		client.CloseIdleConnections()
		r, err = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			t.Fatal("lock release", err)
		}
		r.Close()
	}
}

func TestPublicShutdownDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	expired := make(chan struct{}, 1)
	go publicShutdownDeadline(ctx, done, 20*time.Millisecond, func() { expired <- struct{}{} })
	cancel()
	select {
	case <-expired:
	case <-time.After(time.Second):
		t.Fatal("deadline not enforced")
	}
	ctx, cancel = context.WithCancel(t.Context())
	done = make(chan struct{})
	returned := make(chan struct{})
	go func() {
		publicShutdownDeadline(ctx, done, 20*time.Millisecond, func() { expired <- struct{}{} })
		close(returned)
	}()
	close(done)
	cancel()
	<-returned
	select {
	case <-expired:
		t.Fatal("clean close forced exit")
	default:
	}
}
