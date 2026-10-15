// 公開起動CLIが管理専用TLSを開き、更新・終了と公開経路の分離を保つことを検証する。
package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
	"strings"
	"testing"
	"time"
)

func TestPublicAdminServeLifecycle(t *testing.T) {
	testPublicAdminServeLifecycle(t, false)
}

func TestHiddenAdminServeLifecycle(t *testing.T) {
	testPublicAdminServeLifecycle(t, true)
}

// testPublicAdminServeLifecycle は専用HTTPSと隠しパスで実接続・証明書更新・正常終了を照合する。
func testPublicAdminServeLifecycle(t *testing.T, hidden bool) {
	t.Helper()
	cfg, client, rotate := publicFixture(t)
	cfg.Admin.Transport = "direct_https"
	cfg.Admin.Origin = "https://" + cfg.Admin.Listen
	if hidden {
		cfg.Admin.Transport = "public_path"
		cfg.Admin.Origin = cfg.Public.BaseURL + "/_manage-0123456789abcdef0123456789abcdef"
	}
	if _, err := bootstrap.Initialize(cfg, "公開管理試験"); err != nil {
		t.Fatal(err)
	}
	repo, err := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.ConfigureAdministrator("owner", "所有者", "public-admin-test-secret-0001", false); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repo.EnableAdmission(); err != nil {
		repo.Close()
		t.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- serveConfiguredWithNetworkClient(ctx, cfg, false, "", "", "", io.Discard, true, nil, true, offlineNetworkClient())
	}()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("shutdown did not complete")
		}
	}()
	var response *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		response, err = client.Get(cfg.Admin.Origin + "/login")
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("admin HTTPS startup", err)
	}
	response.Body.Close()
	if response.StatusCode != 200 || response.ProtoMajor != 2 || !strings.Contains(response.Header.Get("X-Robots-Tag"), "noindex") {
		t.Fatal("HTTPS admin", response.StatusCode, response.Proto, response.Header)
	}
	if len(response.Cookies()) != 1 || !response.Cookies()[0].Secure {
		t.Fatal("insecure login cookie")
	}
	if hidden {
		if response.Cookies()[0].Path != "/_manage-0123456789abcdef0123456789abcdef/" {
			t.Fatal("hidden cookie scope")
		}
		unused, err := net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			t.Fatal("hidden mode opened a second admin listener", err)
		}
		unused.Close()
	}

	response, err = client.Get(cfg.Public.BaseURL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 404 {
		t.Fatal("admin leaked into public router", response.StatusCode)
	}
	rotate(2)
	client.CloseIdleConnections()
	response, err = client.Get(cfg.Admin.Origin + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(raw) != "User-agent: *\nDisallow: /\n" || response.TLS.PeerCertificates[0].SerialNumber.Int64() != 2 {
		t.Fatal("certificate reload and robots", err, string(raw))
	}
	request, err := http.NewRequest("GET", cfg.Admin.Origin+"/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("User-Agent", "GPTBot")
	response, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 || len(response.Cookies()) != 0 {
		t.Fatal("crawler reached login", response.StatusCode)
	}
}
