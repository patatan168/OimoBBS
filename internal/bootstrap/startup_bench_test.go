// 圧縮回線表を含む制御履歴の再検査と、投稿対応リポジトリーの起動全体を計測する。
package bootstrap

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/identity"
	"oimobbs/internal/postcapture"
)

// BenchmarkPostingStartup は同じ分類表を保持した8回の更新履歴を毎回検査する。
// OSのファイルキャッシュは共有し、ネットワーク取得・fixture作成・Closeは計測から除く。
func BenchmarkPostingStartup(b *testing.B) {
	benchmarkPostingStartup(b, false)
}

// BenchmarkHTTPStartup はリポジトリー復旧から実TCPで板一覧を読み終えるまでを計測する。
// 公開CLIの保守設定変更とTLSは含まない。各回の復号キャッシュは空にする。
func BenchmarkHTTPStartup(b *testing.B) {
	benchmarkPostingStartup(b, true)
}

// benchmarkPostingStartup は同じ永続データで復旧とHTTP受付を比較する。
func benchmarkPostingStartup(b *testing.B, probeHTTP bool) {
	cfg := startupBenchmarkConfig(b)
	client := &http.Client{Timeout: 10 * time.Second}
	defer client.CloseIdleConnections()
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		b.StopTimer()
		// プロセス内の前回起動の復号結果を借りず、起動ごとに最初の表を完全検査する。
		decodedNetworkRows = networkRowsCache{}
		b.StartTimer()
		repo, err := OpenPostingRepository(cfg, postcapture.Validate)
		if err != nil {
			b.Fatal(err)
		}
		var server *http.Server
		if probeHTTP {
			server = probeStartupHTTP(b, repo, client)
		}
		b.StopTimer()
		if server != nil {
			if err = server.Close(); err != nil {
				b.Fatal(err)
			}
		}
		if err = repo.Close(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

// startupBenchmarkConfig は外部取得を無効にした圧縮表と更新履歴を永続保存する。
func startupBenchmarkConfig(b *testing.B) Config {
	cfg := testConfig(b)
	if _, err := Initialize(cfg, "起動計測"); err != nil {
		b.Fatal(err)
	}
	repo, err := OpenRepository(cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { repo.Close() })
	if _, err = repo.CreateBoard(b.Context(), "startup", "起動計測"); err != nil {
		b.Fatal(err)
	}
	next := networkState{Version: 1, Config: defaultNetworkConfig(), Rows: networkRows{}}
	for i := range 12000 {
		next.Rows = append(next.Rows, identity.NetworkClass{CIDR: fmt.Sprintf("198.18.%d.%d/32", i/256, i%256), Kind: "hosting", Label: "ｸﾓﾉｳｴ", Suffix: "V", Provider: "cloud"})
	}
	for i := range 8 {
		next.LastAttempt, next.LastSuccess = domain.Time(i+1), domain.Time(i+1)
		next.AttemptVersion, next.AppliedVersion = 1, 1
		// 時刻だけが変わっても表の全行を再検証する旧経路を再現する。
		if err = repo.publishNetworks(next, nil, "network_refresh", nil); err != nil {
			b.Fatal(err)
		}
	}
	// 初回だけのHTTP設定保存を済ませ、すべての試行を同じ設定で再開する。
	server, err := repo.ValidationHTTPServer()
	if err != nil {
		b.Fatal(err)
	}
	if err = server.Close(); err != nil {
		b.Fatal(err)
	}
	if err = repo.Close(); err != nil {
		b.Fatal(err)
	}
	return cfg
}

// probeStartupHTTP はループバックの実TCPで公開メニューと板のHTTP 200を検査する。
func probeStartupHTTP(b *testing.B, repo *Repository, client *http.Client) *http.Server {
	b.Helper()
	server, err := repo.ValidationHTTPServer()
	if err != nil {
		b.Fatal(err)
	}
	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go server.Serve(socket)
	origin, err := url.Parse(repo.cfg.Public.BaseURL)
	if err != nil {
		server.Close()
		b.Fatal(err)
	}
	for _, path := range []string{"/bbsmenu.json", "/startup/subject.txt"} {
		request, err := http.NewRequest(http.MethodGet, "http://"+socket.Addr().String()+path, nil)
		if err != nil {
			server.Close()
			b.Fatal(err)
		}
		request.Host = origin.Host
		response, err := client.Do(request)
		if err != nil {
			server.Close()
			b.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil {
			server.Close()
			b.Fatal("startup HTTP", response.StatusCode, readErr, closeErr)
		}
	}
	return server
}
