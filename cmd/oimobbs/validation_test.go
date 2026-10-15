// 検証CLIが既存保存先を保持し、停止時に排他を解放することを確認する。
package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
)

func TestValidationServerLifecycle(t *testing.T) {
	root := t.TempDir()
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().String()
	socket.Close()
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(root, "site"), Public: bootstrap.PublicConfig{Listen: address, BaseURL: "http://" + address}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:9081", Transport: "loopback_tunnel", Origin: "http://127.0.0.1:9081"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	client := &http.Client{Timeout: time.Second}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- serveConfiguredWithNetworkClient(ctx, cfg, true, "検証サイト", "oimo", "検証板", io.Discard, false, nil, false, offlineNetworkClient())
		}()
		deadline := time.Now().Add(5 * time.Second)
		ready := false
		for time.Now().Before(deadline) {
			response, e := client.Get(cfg.Public.BaseURL + "/bbsmenu.json")
			if e == nil {
				response.Body.Close()
				ready = response.StatusCode == 200 && response.Header.Get("X-Oimo-Environment") == "validation"
				if ready {
					break
				}
			}
			select {
			case e := <-done:
				cancel()
				t.Fatal("server exited", e)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		if !ready {
			t.Fatal("server did not become ready")
		}
		repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
		if e != nil {
			t.Fatal("lock not released", e)
		}
		boards, e := repo.Boards()
		repo.Close()
		if e != nil || len(boards) != 1 {
			t.Fatal("initial board duplicated/lost", e, boards)
		}
	}
	// 初期化途中を初期化し直したり、自動削除したりしない。
	cfg.DataDir = filepath.Join(root, "incomplete")
	if err = os.Mkdir(cfg.DataDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = serveConfiguredWithNetworkClient(context.Background(), cfg, true, "検証サイト", "", "", io.Discard, false, nil, false, offlineNetworkClient()); err == nil {
		t.Fatal("incomplete data overwritten")
	}
	if _, err = os.Stat(cfg.DataDir); err != nil {
		t.Fatal("incomplete data removed")
	}
}
