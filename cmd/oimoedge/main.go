// Command oimoedge は掲示板データを持たない公開入口と、その専用mTLS証明書を扱う。
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"oimobbs/internal/publicedge"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: oimoedge serve|init-client")
	}
	f := flag.NewFlagSet(args[0], flag.ContinueOnError)
	if args[0] == "probe" {
		origin := f.String("origin", "", "公開HTTPS origin")
		address := f.String("address", "127.0.0.1:8443", "検査する公開入口socket")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		u, err := url.Parse(*origin)
		if err != nil || u.Scheme != "https" || u.Host == "" || f.NArg() != 0 {
			return errors.New("HTTPS probe origin required")
		}
		tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, *address)
		}}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		res, err := client.Get(*origin + "/_edge/health")
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return errors.New("public edge probe failed")
		}
		return nil
	}
	if args[0] == "init-client" {
		output := f.String("output", "", "新規0700証明書directory")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if *output == "" || f.NArg() != 0 {
			return errors.New("output required")
		}
		return initializeClient(*output)
	}
	if args[0] != "serve" {
		return errors.New("unknown edge action")
	}
	var c publicedge.Config
	f.StringVar(&c.Listen, "listen", "0.0.0.0:8443", "公開待受")
	f.StringVar(&c.Origin, "origin", "", "公開HTTPS origin")
	f.StringVar(&c.Upstream, "upstream", "", "固定保存サーバーHTTPS origin")
	f.StringVar(&c.AdminPath, "admin-path", "", "同じ公開HTTPSで扱う管理パス（末尾の/なし）")
	f.StringVar(&c.ClientCert, "client-cert", "/edge/client.pem", "mTLS client証明書")
	f.StringVar(&c.ClientKey, "client-key", "/edge/client.key", "mTLS client鍵")
	f.StringVar(&c.ServerCert, "server-cert", "/tls/server.pem", "公開TLS証明書")
	f.StringVar(&c.ServerKey, "server-key", "/tls/server.pem", "公開TLS鍵")
	if err := f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return publicedge.Serve(ctx, c)
}

// initializeClient は専用CAとclientを一度だけ生成する。CA秘密鍵は保存しない。
func initializeClient(dir string) error {
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(caKey)
	defer clear(key)
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OimoBBS private edge CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "public-edge"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caKey)
	if err != nil {
		return err
	}
	pk, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	defer clear(pk)
	for _, v := range []struct {
		name, typ string
		raw       []byte
	}{{"ca.pem", "CERTIFICATE", caDER}, {"client.pem", "CERTIFICATE", der}, {"client.key", "PRIVATE KEY", pk}} {
		f, err := os.OpenFile(filepath.Join(dir, v.name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		err = pem.Encode(f, &pem.Block{Type: v.typ, Bytes: v.raw})
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	hash := sha256.Sum256(der)
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"client_certificate_sha256": hex.EncodeToString(hash[:]), "expires": leaf.NotAfter.UTC().Format(time.RFC3339)})
}
