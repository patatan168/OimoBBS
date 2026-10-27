// 検証用HTTPサーバーの起動部品。製品の規制・保持期限運用の完成を表さない。
package bootstrap

import (
	"context"
	"crypto/tls"
	"net/http"
	"oimobbs/internal/delivery"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strings"
	"time"
)

// ValidationHTTPServer は直結の接続観測と有界同時処理を設定した検証用サーバーを作る。
// Listen・Shutdown・Repository.Closeは呼出元が管理する。public_path設定時は隠し管理ルートも登録する。
func (repo *Repository) ValidationHTTPServer() (*http.Server, error) {
	return repo.publicHTTPServer("validation", "validation-v1")
}

// publicHTTPServer は公開/検証で同じ接続・要求・送信上限を使う。
func (repo *Repository) publicHTTPServer(environment, build string) (*http.Server, error) {
	origin, originErr := parseOrigin(repo.cfg.Public.BaseURL)
	if originErr != nil {
		return nil, originErr
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return repo.cfg.loadTLSCertificate(time.Now()) }}
	// 証明書信頼設定の失敗ではreaderや保存領域を変更しない。
	if err := repo.cfg.edgeTLS(tlsConfig); err != nil {
		return nil, err
	}
	repo.mu.Lock()
	var site siteState
	err := repo.available()
	if err == nil {
		err = strictjson.Decode(repo.site.State().Rows["site:state"].Value, &site)
	}
	if err == nil && repo.cfg.Edge != nil && site.MinimumReader < 62 {
		site.MinimumReader = 62
		err = appendControl(repo.site, "edge_enable", []store.Mutation{mutation("site", "state", site, nil)}, []string{})
		if err != nil {
			repo.stopped = true
		}
	}
	if err == nil {
		err = repo.enableSpecialNetworkHosts()
	}
	if err == nil {
		err = repo.enablePostingResources()
	}
	if err == nil && repo.egress == nil {
		repo.egress, err = delivery.New(repo.operations().EgressBits)
	}
	if err == nil {
		err = repo.ensureOptionalLogs()
	}
	queue := repo.optionalQueue
	egress := repo.egress
	repo.mu.Unlock()
	if err != nil {
		return nil, err
	}
	// 単一インスタンス構成では永続site IDをinstance IDとしても使う。
	observer, err := evidence.NewHTTPObserver(site.ID, site.ID, build)
	if err != nil {
		return nil, err
	}
	handler := repo.SiteWebHandler(observer)
	gate, _ := delivery.NewRequestGate(2048, 32)
	server := &http.Server{Addr: repo.cfg.Public.Listen, ConnContext: observer.ConnContext, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	// 要求枠へ入る前のHTTP/2 streamと受信windowも有界にする。
	server.HTTP2 = &http.HTTP2Config{MaxConcurrentStreams: 32, MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 256 << 10, MaxReceiveBufferPerStream: 64 << 10, WriteByteTimeout: 10 * time.Second}
	server.RegisterOnShutdown(gate.Close)
	server.Handler = egress.Wrap(gate.Wrap(repo.memoryHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oimo-Environment", environment)
		handler.ServeHTTP(w, r)
	}))))
	server.Handler = observer.WrapOptional(repo.cfg.edgeHandler(repo.wafIngressHandler(repo.trafficHandler(repo.wafHandler(server.Handler), false), origin, evidence.MaxObservedBodyBytes)), queue, classifyOptionalHTTP)
	if repo.cfg.Public.TLSCert != "" {
		server.TLSConfig = tlsConfig
	}

	if repo.cfg.Admin.Transport == "public_path" {
		admin, err := repo.AdminHTTPServer()
		if err != nil {
			return nil, err
		}
		_, base, _ := repo.cfg.adminEndpoint()
		// 管理要求もmTLSと実peerを検査してから利用者IPへ解決する。公開HTTPログは通さない。
		adminRoutes := repo.cfg.edgeHandler(admin.Handler)
		public := server.Handler
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == base || strings.HasPrefix(r.URL.Path, base+"/") {
				adminRoutes.ServeHTTP(w, r)
				return
			}
			public.ServeHTTP(w, r)
		})
		server.RegisterOnShutdown(func() { _ = admin.Shutdown(context.Background()) })
	}
	server.Handler = securityTransportHeaders(server.Handler)
	return server, nil
}

// DeliveryStatus は公開/管理共通の送信枠を、主体を含まない集計で返す。
func (repo *Repository) DeliveryStatus() delivery.Status {
	repo.mu.Lock()
	scheduler := repo.egress
	repo.mu.Unlock()
	if scheduler == nil {
		return delivery.Status{Budget: repo.operations().EgressBits}
	}
	return scheduler.Status()
}
