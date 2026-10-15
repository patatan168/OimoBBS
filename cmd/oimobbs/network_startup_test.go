// 初回サーバー起動の取得要求を外部ネットワークへ出さずに検証する。
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"oimobbs/internal/bootstrap"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type offlineNetworkTransport struct{}

func (offlineNetworkTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(""))}, nil
}

// offlineNetworkClient は外部障害を決定的に再現し、CLI試験をインターネットに依存させない。
func offlineNetworkClient() *http.Client { return &http.Client{Transport: offlineNetworkTransport{}} }

// trackingStartupTransport は初回起動が要求したASNを記録し、外部障害を再現する。
type trackingStartupTransport struct {
	mu    sync.Mutex
	asns  map[uint32]bool
	ready chan struct{}
}

func (transport *trackingStartupTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	var asn uint32
	if _, err := fmt.Sscanf(request.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn); err == nil {
		transport.mu.Lock()
		first := !transport.asns[asn]
		transport.asns[asn] = true
		if first && len(transport.asns) == 180 {
			close(transport.ready)
		}
		transport.mu.Unlock()
	}
	return offlineNetworkTransport{}.RoundTrip(request)
}

func TestServeFirstStartupFetchesDomesticNetworks(t *testing.T) {
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := socket.Addr().String()
	socket.Close()
	cfg := bootstrap.Config{Schema: 1, DataDir: filepath.Join(t.TempDir(), "site"), Public: bootstrap.PublicConfig{Listen: address, BaseURL: "http://" + address}, Admin: bootstrap.AdminConfig{Listen: "127.0.0.1:9081", Transport: "loopback_tunnel", Origin: "http://127.0.0.1:9081"}, TrustedProxies: []string{}, CacheBytes: 268435456, EgressBits: 80000000}
	transport := &trackingStartupTransport{asns: map[uint32]bool{}, ready: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- serveConfiguredWithNetworkClient(ctx, cfg, true, "国内取得", "", "", io.Discard, false, nil, false, &http.Client{Transport: transport})
	}()
	defer cancel()
	deadline := time.After(5 * time.Second)
	select {
	case <-transport.ready:
	case err := <-done:
		t.Fatal("startup exited", err)
	case <-deadline:
		t.Fatal("first startup did not request full domestic catalog")
	}
	client := &http.Client{Timeout: time.Second}
	for {
		response, e := client.Get(cfg.Public.BaseURL + "/bbsmenu.json")
		if e == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				break
			}
		}
		select {
		case <-deadline:
			t.Fatal("feed failure blocked server readiness")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	transport.mu.Lock()
	count := len(transport.asns)
	sony := transport.asns[2527] && transport.asns[9600]
	rakuten := transport.asns[138384] && transport.asns[10012]
	transport.mu.Unlock()
	if count != 211 || !sony || !rakuten {
		t.Fatal("domestic startup coverage", count, sony, rakuten)
	}
	repo, err := bootstrap.OpenRepository(cfg)
	if err != nil {
		t.Fatal("initial networks not reopenable", err)
	}
	repo.Close()
}
