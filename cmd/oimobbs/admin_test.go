// 管理CLIの秘密入力・再設定と、管理リスナーの起動終了を実ソケットで確認する。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
)

func TestAdministratorCLIAndListener(t *testing.T) {
	address := func() string {
		t.Helper()
		s, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		a := s.Addr().String()
		s.Close()
		return a
	}
	public, admin := address(), address()
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(t.TempDir(), "site"), Public: bootstrap.PublicConfig{Listen: public, BaseURL: "http://" + public}, Admin: bootstrap.AdminConfig{Listen: admin, Origin: "http://" + admin, Transport: "loopback_tunnel"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	if _, e := bootstrap.Initialize(cfg, "CLI試験"); e != nil {
		t.Fatal(e)
	}
	if e := serveConfiguredWithNetworkClient(context.Background(), cfg, false, "", "", "", io.Discard, true, nil, false, offlineNetworkClient()); e == nil {
		t.Fatal("admin listener without administrator")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	raw, _ := json.Marshal(cfg)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	invoke := func(command, password string) (bootstrap.AdministratorInfo, error) {
		t.Helper()
		var out bytes.Buffer
		e := runAdmin([]string{command, "--config", path, "--login", "owner", "--password-stdin"}, strings.NewReader(password+"\n"), &out, io.Discard)
		if strings.Contains(out.String(), password) || strings.Contains(out.String(), "digest") {
			t.Fatal("secret in output")
		}
		var info bootstrap.AdministratorInfo
		if e == nil {
			e = json.Unmarshal(out.Bytes(), &info)
		}
		return info, e
	}
	first, e := invoke("init", "initial-password-for-admin")
	if e != nil || first.Generation != 1 {
		t.Fatal("init", e)
	}
	if _, e = invoke("init", "initial-password-for-admin"); e == nil {
		t.Fatal("duplicate init")
	}
	var resetOutput bytes.Buffer
	if err := runAdmin([]string{"reset-reading-access", "--config", path}, strings.NewReader(""), &resetOutput, io.Discard); err != nil || !strings.Contains(resetOutput.String(), "admin_reading_access_disabled") {
		t.Fatal("reading reset CLI", err, resetOutput.String())
	}
	next, e := invoke("reset-password", "replacement-password-for-admin")
	if e != nil || next.ID != first.ID || next.Generation != 2 {
		t.Fatal("reset", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveConfiguredWithNetworkClient(ctx, cfg, false, "", "", "", io.Discard, true, nil, false, offlineNetworkClient())
	}()
	client := &http.Client{Timeout: time.Second}
	ready := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := client.Get(cfg.Admin.Origin + "/login")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				ready = true
				break
			}
		}
		select {
		case e := <-done:
			t.Fatal("early exit", e)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown timeout")
	}
	if !ready {
		t.Fatal("admin listener not ready")
	}
	for _, a := range []string{public, admin} {
		s, e := net.Listen("tcp", a)
		if e != nil {
			t.Fatal("listener not released", e)
		}
		s.Close()
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		t.Fatal("repository lock not released", e)
	}
	repo.Close()
}
