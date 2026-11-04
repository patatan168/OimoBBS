// 保存不明・所有worker終了をHTTP監視へ伝え、正常な別板と再起動復旧を維持することを確認する。
package bootstrap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"oimobbs/internal/domain"
	"oimobbs/internal/publicedge"
	"oimobbs/internal/store"
	"oimobbs/internal/waf"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const healthcheckTestPath = "/.well-known/oimobbs-health"

// healthcheckRequest は公開ルーターへ圧縮受入を宣言した要求を送り、監視応答を取得する。
func healthcheckRequest(t *testing.T, repo *Repository, cfg Config, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, cfg.Public.BaseURL+path, nil)
	r.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	repo.SiteWebHandler(nil).ServeHTTP(w, r)
	return w
}

func TestHealthcheckStorageFailureAndRecovery(t *testing.T) {
	cfg, repo, first := postingRepositoryFixture(t)
	other, err := repo.CreateBoard(t.Context(), "other", "正常な板")
	if err != nil {
		t.Fatal(err)
	}
	if w := healthcheckRequest(t, repo, cfg, http.MethodGet, healthcheckTestPath); w.Code != 200 || w.Body.String() != "ok\n" {
		t.Fatal("initial readiness", w.Code, w.Body.String())
	}
	b := repo.posting[first.ID]
	now := time.Now()
	b.clock = func() time.Time { return now }
	if _, err := b.journal(now); err != nil {
		t.Fatal(err)
	}
	// 初回のjournal保存先に実ディレクトリの競合を作り、公開Postの保存不明を発生させる。
	conflict := filepath.Join(b.evidenceDir, now.UTC().Format("20060102"))
	if err := os.Mkdir(conflict, 0700); err != nil {
		t.Fatal(err)
	}
	frame := persistentFrame(t)
	failed := repo.Post(t.Context(), first.ID, 0, frame, []byte(`{"fixture":true}`))
	if failed.Status != store.Unknown {
		t.Fatal("failure not propagated", failed)
	}
	if w := healthcheckRequest(t, repo, cfg, "GET", healthcheckTestPath); w.Code != 503 || w.Body.String() != "unavailable\n" {
		t.Fatal("stopped writer reported healthy", w.Code, w.Body.String())
	}
	for path, want := range map[string]int{"/": 200, "/news/subject.txt": 503, "/other/subject.txt": 200} {
		if w := healthcheckRequest(t, repo, cfg, "GET", path); w.Code != want {
			t.Fatal(path, w.Code, want)
		}
	}
	saved := repo.Post(t.Context(), other.ID, 0, frame, []byte(`{"fixture":true}`))
	if saved.Status != store.Durable {
		t.Fatal("other board stopped", saved)
	}
	snapshot, err := repo.Thread(t.Context(), other.ID, saved.ThreadKey)
	if err != nil || snapshot == nil {
		t.Fatal("other board unreadable", snapshot, err)
	}
	datPath := fmt.Sprintf("/other/dat/%d.dat", saved.ThreadKey)
	before := healthcheckRequest(t, repo, cfg, "GET", datPath)
	if before.Code != 200 || !bytes.Equal(before.Body.Bytes(), snapshot.DAT) || before.Header().Get("ETag") == "" {
		t.Fatal("other board DAT unavailable", before.Code, before.Header())
	}
	if err := os.Remove(conflict); err != nil {
		t.Fatal(err)
	}
	if w := healthcheckRequest(t, repo, cfg, "GET", healthcheckTestPath); w.Code != 503 {
		t.Fatal("stop latch cleared without recovery", w.Code)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenPostingRepository(cfg, postingCaptureFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if w := healthcheckRequest(t, reopened, cfg, "GET", healthcheckTestPath); w.Code != 200 {
		t.Fatal("recovered writer unhealthy", w.Code)
	}
	if saved := reopened.Post(t.Context(), first.ID, 0, frame, []byte(`{"fixture":true}`)); saved.Status != store.Durable {
		t.Fatal("posting after recovery", saved)
	}
	if recovered, err := reopened.Thread(t.Context(), other.ID, saved.ThreadKey); err != nil || recovered == nil || !bytes.Equal(recovered.DAT, snapshot.DAT) || recovered.PostCount != snapshot.PostCount {
		t.Fatal("other board lost after recovery", recovered, err)
	}
	after := healthcheckRequest(t, reopened, cfg, "GET", datPath)
	if after.Code != 200 || !bytes.Equal(after.Body.Bytes(), before.Body.Bytes()) || after.Header().Get("ETag") != before.Header().Get("ETag") {
		t.Fatal("other board DAT changed after recovery", after.Code, after.Header())
	}
}

func TestHealthcheckStorageStates(t *testing.T) {
	for _, state := range []string{"ready", "site-stopped", "closed", "board-stopped", "worker-ended", "hidden-stopped", "board-closed", "hidden-ready"} {
		t.Run(state, func(t *testing.T) {
			cfg, repo, info := postingRepositoryFixture(t)
			b := repo.posting[info.ID]
			want := 503
			switch state {
			case "ready":
				want = 200
			case "site-stopped":
				repo.mu.Lock()
				repo.stopped = true
				repo.mu.Unlock()
			case "closed":
				if err := repo.Close(); err != nil {
					t.Fatal(err)
				}
			case "worker-ended":
				b.worker.Close()
			default:
				_, err := b.worker.Submit(t.Context(), func() (any, error) {
					switch state {
					case "board-closed":
						b.closePublic(domain.Time(time.Now().UnixNano()))
					case "hidden-ready":
						b.hidden.Store(true)
					case "hidden-stopped":
						b.hidden.Store(true)
						b.stopped = true
					default:
						b.stopped = true
					}
					return nil, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				if state == "board-closed" || state == "hidden-ready" {
					want = 200
				}
			}
			w := healthcheckRequest(t, repo, cfg, "GET", healthcheckTestPath)
			if w.Code != want {
				t.Fatal(state, w.Code, want)
			}
			if w.Header().Get("Cache-Control") != "no-store" || len(w.Result().Cookies()) != 0 {
				t.Fatal("readiness cache or cookies", w.Header())
			}
			if w.Body.String() != "ok\n" && w.Body.String() != "unavailable\n" {
				t.Fatal("unexpected public detail", w.Body.String())
			}
			head := healthcheckRequest(t, repo, cfg, "HEAD", healthcheckTestPath)
			if head.Code != want || head.Body.Len() != 0 || head.Header().Get("Content-Length") != w.Header().Get("Content-Length") {
				t.Fatal("HEAD readiness differs", head.Code, head.Header())
			}
		})
	}
}

func TestHealthcheckDoesNotWaitForBusyBoard(t *testing.T) {
	cfg, repo, info := postingRepositoryFixture(t)
	started, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = repo.posting[info.ID].worker.Submit(context.Background(), func() (any, error) { close(started); <-release; return nil, nil })
	}()
	<-started
	defer func() { close(release); <-finished }()
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- healthcheckRequest(t, repo, cfg, "GET", healthcheckTestPath) }()
	select {
	case w := <-response:
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readiness waited for board worker")
	}
}

func TestHealthcheckHTTPContract(t *testing.T) {
	cfg, repo, _ := postingRepositoryFixture(t)
	for _, method := range []string{"GET", "HEAD", "POST"} {
		w := healthcheckRequest(t, repo, cfg, method, healthcheckTestPath)
		want := 200
		if method == "POST" {
			want = 405
		}
		if w.Code != want {
			t.Fatal(method, w.Code, w.Body.String())
		}
		if method == "HEAD" && w.Body.Len() != 0 {
			t.Fatal("HEAD returned body")
		}
		if method == "POST" && w.Header().Get("Allow") != "GET, HEAD" {
			t.Fatal("missing Allow")
		}
		if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("ETag") != "" || len(w.Result().Cookies()) != 0 {
			t.Fatal("unsafe health response", w.Header())
		}
	}
}

func TestHealthcheckEmptySiteAndRequestBoundary(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "空のサイト"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenPostingRepository(cfg, postingCaptureFixture)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if w := healthcheckRequest(t, repo, cfg, "GET", healthcheckTestPath); w.Code != 200 {
		t.Fatal("empty site unhealthy", w.Code)
	}
	for _, target := range []string{"http://other.invalid" + healthcheckTestPath, cfg.Public.BaseURL + "/%2ewell-known/oimobbs-health"} {
		r := httptest.NewRequest("GET", target, nil)
		r.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		repo.SiteWebHandler(nil).ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("invalid authority or path accepted", target, w.Code)
		}
	}
}

func TestHealthcheckTLSAndAuthenticatedEdge(t *testing.T) {
	for _, mode := range []string{"direct", "edge"} {
		for _, h2 := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/http1", true: "/http2"}[h2], func(t *testing.T) {
				cfg := testConfig(t)
				clientTLS, _ := proxyCertificates(t, &cfg)
				if mode == "direct" {
					cfg.Edge, cfg.TrustedProxies = nil, []string{}
					clientTLS.Certificates = nil
				}
				if _, err := Initialize(cfg, "実TLS監視"); err != nil {
					t.Fatal(err)
				}
				repo, err := OpenPostingRepository(cfg, postingCaptureFixture)
				if err != nil {
					t.Fatal(err)
				}
				defer repo.Close()
				info, err := repo.CreateBoard(t.Context(), "news", "監視板")
				if err != nil {
					t.Fatal(err)
				}
				configured, err := repo.ValidationHTTPServer()
				if err != nil {
					t.Fatal(err)
				}
				policy := WAFSettings{Enabled: true, Traffic: waf.DefaultTrafficSettings()}
				policy.Traffic.Enabled = false
				repo.publishWAF(policy)
				backend := httptest.NewUnstartedServer(configured.Handler)
				backend.Config, backend.EnableHTTP2 = configured, h2
				if h2 {
					configured.TLSConfig.NextProtos = []string{"h2", "http/1.1"}
				}
				backend.TLS = configured.TLSConfig.Clone()
				backend.StartTLS()
				defer backend.Close()
				transport := &http.Transport{TLSClientConfig: clientTLS, ForceAttemptHTTP2: h2}
				defer transport.CloseIdleConnections()
				client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
				address := backend.URL
				if mode == "edge" {
					upstream, _ := url.Parse(backend.URL)
					proxy, err := publicedge.Handler(cfg.Public.BaseURL, upstream, transport)
					if err != nil {
						t.Fatal(err)
					}
					front := httptest.NewUnstartedServer(proxy)
					front.EnableHTTP2 = h2
					front.StartTLS()
					defer front.Close()
					client, address = front.Client(), front.URL
					client.Timeout = 3 * time.Second
					defer client.CloseIdleConnections()
				}
				origin, _ := url.Parse(cfg.Public.BaseURL)
				request := func(path, agent string) (int, string) {
					t.Helper()
					r, _ := http.NewRequest("GET", address+path, nil)
					r.Host = origin.Host
					r.Header.Set("User-Agent", agent)
					response, err := client.Do(r)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					if err != nil || response.ProtoMajor != map[bool]int{false: 1, true: 2}[h2] {
						t.Fatal("protocol or body", response.Proto, err)
					}
					return response.StatusCode, string(body)
				}
				if !h2 {
					for _, path := range []string{healthcheckTestPath, "/"} {
						if status, body := request(path, "health-fixture"); status != 505 || body != "" {
							t.Fatal("HTTP/1 public route accepted", path, status, body)
						}
					}
					if status, _ := request("/news/subject.txt", "health-fixture"); status != 200 {
						t.Fatal("HTTP/1 legacy feed denied", status)
					}
					return
				}
				if status, body := request(healthcheckTestPath, "health-fixture"); status != 200 || body != "ok\n" {
					t.Fatal("healthy TLS route", status, body)
				}
				if status, _ := request(healthcheckTestPath, strings.Repeat("a", 1025)); status != 403 {
					t.Fatal("WAF bypassed", status)
				}
				b := repo.posting[info.ID]
				if _, err := b.worker.Submit(t.Context(), func() (any, error) { b.stopped = true; return nil, nil }); err != nil {
					t.Fatal(err)
				}
				if status, body := request(healthcheckTestPath, "health-fixture"); status != 503 || body != "unavailable\n" {
					t.Fatal("stopped TLS route", status, body)
				}
				if status, _ := request("/", "health-fixture"); status != 200 {
					t.Fatal("home route changed", status)
				}
			})
		}
	}
}
