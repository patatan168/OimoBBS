// 並列取得の上限・取消・全件成功の境界を、外部通信なしで検証する。
package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// gatedNetworkClient は要求開始を通知し、解放まで本文の生成を止める。
func gatedNetworkClient(started chan<- struct{}, release <-chan struct{}, peak *atomic.Int32) *http.Client {
	var active atomic.Int32
	return &http.Client{Transport: networkTestTransport(func(req *http.Request) (*http.Response, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case started <- struct{}{}:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		select {
		case <-release:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		var raw []byte
		switch {
		case strings.Contains(req.URL.Path, "/refs/heads/"):
			w := httptest.NewRecorder()
			writeCountryFixture(w)
			raw = w.Body.Bytes()
		case strings.HasSuffix(req.URL.Path, "/jp/jp.json"):
			raw = []byte(`{"countryCode":"JP","prefixes":{"ipv4":["1.1.0.0/16"],"ipv6":["2400::/32"]}}`)
		case strings.HasSuffix(req.URL.Path, "/ipv4.txt"):
			raw = []byte("2.2.0.0/16\n")
		case strings.HasSuffix(req.URL.Path, "/ipv6.txt"):
			raw = []byte("2600::/32\n")
		default:
			var asn uint32
			if _, err := fmt.Sscanf(req.URL.Path, "/ipverse/as-ip-blocks/master/as/%d/aggregated.json", &asn); err != nil {
				return nil, err
			}
			raw = []byte(fmt.Sprintf(`{"asn":%d,"prefixes":{"ipv4":["3.3.0.0/16"],"ipv6":[]}}`, asn))
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(raw)), Request: req}, nil
	})}
}

func TestNetworkAccessParallel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	started := make(chan struct{}, 32)
	release := make(chan struct{})
	var peak atomic.Int32
	done := make(chan error, 1)
	go func() {
		data, err := fetchAccessData(ctx, gatedNetworkClient(started, release, &peak), defaultAccessSources())
		if err == nil && (data.Countries == "" || len(data.Japan) != 2 || len(data.VPN4) != 1 || len(data.VPN6) != 1) {
			err = errNetworkData
		}
		done <- err
	}()
	for range 4 {
		select {
		case <-started:
		case <-ctx.Done():
			close(release)
			<-done
			t.Fatal("国・日本・VPNの両familyを同時取得できなかった")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestNetworkUpdateSharedConcurrencyLimit(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	started := make(chan struct{}, 32)
	release := make(chan struct{})
	var peak atomic.Int32
	sources := defaultAccessSources()
	for i := 0; i < 12; i++ {
		sources = append(sources, NetworkSource{Name: fmt.Sprint(i), Type: "asn", ASN: uint32(100 + i), Kind: "hosting", Label: "クラウド", Suffix: "V"})
	}
	done := make(chan error, 1)
	go func() {
		rows, access, err := fetchNetworkUpdate(ctx, gatedNetworkClient(started, release, &peak), sources)
		if err == nil && (len(rows) != 1 || access == nil || access.Countries == "") {
			err = errNetworkData
		}
		done <- err
	}()
	for range 8 {
		select {
		case <-started:
		case <-ctx.Done():
			close(release)
			<-done
			t.Fatal("取得workerが開始しない")
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if peak.Load() > 8 {
		t.Fatal("同時取得上限を超えた", peak.Load())
	}
}

func TestNetworkUpdateCancelledBeforeFetch(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	client := &http.Client{Transport: networkTestTransport(func(*http.Request) (*http.Response, error) {
		t.Error("取消後に取得を開始した")
		return nil, errNetworkFetch
	})}
	if _, _, err := fetchNetworkUpdate(ctx, client, defaultNetworkSources()); err != context.Canceled {
		t.Fatal(err)
	}
}
