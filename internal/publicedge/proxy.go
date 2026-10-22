// Package publicedge は保存領域を開かず、公開HTTPを認証済みの保存サーバーへ渡す。
package publicedge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/delivery"
)

// Config は公開origin、固定転送先、mTLS client鍵と公開TLS鍵だけを持つ。
type Config struct{ Listen, Origin, Upstream, ClientCert, ClientKey, ServerCert, ServerKey, AdminPath string }

// Handler は利用者endpointを実socketから生成し、申告headerを除去して転送する。
// transportは通常の証明書検証とmTLSを備える。任意の転送先は要求から選択しない。
func Handler(origin string, upstream *url.URL, transport http.RoundTripper) (http.Handler, error) {
	return handler(origin, upstream, transport, "")
}

// handler は設定済み管理パスに限ってPATCHと管理用本文上限を許可する。
func handler(origin string, upstream *url.URL, transport http.RoundTripper, adminPath string) (http.Handler, error) {
	if !validAdminPath(adminPath) {
		return nil, errors.New("invalid admin mount path")
	}
	base, err := url.Parse(origin)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil || base.Path != "" || base.RawQuery != "" || base.Fragment != "" || upstream == nil || upstream.Scheme != "https" || upstream.User != nil || upstream.Host == "" || upstream.Path != "" || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("fixed HTTPS origins required")
	}
	proxy := &httputil.ReverseProxy{Transport: transport, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, r *http.Request, e error) {
		http.Error(w, "公開サーバーへ接続できません。", 503)
	}}
	proxy.Rewrite = func(p *httputil.ProxyRequest) {
		p.SetURL(upstream)
		p.Out.Host = base.Host
		for k := range p.Out.Header {
			name := strings.ToLower(k)
			if strings.HasPrefix(name, "x-oimo-") || strings.HasPrefix(name, "x-forwarded-") || name == "forwarded" {
				p.Out.Header.Del(k)
			}
		}
		client, _ := netip.ParseAddrPort(p.In.RemoteAddr)
		local := p.In.Context().Value(http.LocalAddrContextKey).(net.Addr)
		destination, _ := netip.ParseAddrPort(local.String())
		p.Out.Header.Set("X-Oimo-Client-IP", client.Addr().Unmap().String())
		p.Out.Header.Set("X-Oimo-Client-Port", strconv.Itoa(int(client.Port())))
		p.Out.Header.Set("X-Oimo-Dest-IP", destination.Addr().Unmap().String())
		p.Out.Header.Set("X-Oimo-Dest-Port", strconv.Itoa(int(destination.Port())))
		var id [16]byte
		_, err := rand.Read(id[:])
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		p.Out.Header.Set("X-Oimo-Edge-Request", hex.EncodeToString(id[:]))
		p.Out.Header.Set("X-Oimo-Edge-Time", strconv.FormatInt(time.Now().UnixNano(), 10))
		// 不正queryを正規化して別要求へ変えない。業務層の厳格parserへ元の文字列を渡す。
		p.Out.URL.RawQuery = p.In.URL.RawQuery
	}
	gate, _ := delivery.NewRequestGate(128, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if r.TLS == nil || !sameOriginHost(r.Host, base) || !canonicalPath(r) {
			http.Error(w, "要求を確認してください。", 400)
			return
		}
		if r.URL.Path == "/_edge/health" && r.Method == "GET" {
			w.WriteHeader(200)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/login" || r.URL.Path == "/reauth" {
			http.NotFound(w, r)
			return
		}
		admin := adminPath != "" && (r.URL.Path == adminPath || strings.HasPrefix(r.URL.Path, adminPath+"/"))
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "POST" && !(admin && r.Method == "PATCH") {
			allow := "GET, HEAD, POST"
			if admin {
				allow += ", PATCH"
			}
			w.Header().Set("Allow", allow)
			http.Error(w, "許可されない操作です。", 405)
			return
		}
		client, e := netip.ParseAddrPort(r.RemoteAddr)
		local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
		if e != nil || !client.Addr().IsValid() || client.Port() == 0 || !ok {
			http.Error(w, "接続元を確認できません。", 400)
			return
		}
		dest, e := netip.ParseAddrPort(local.String())
		if e != nil || dest.Port() == 0 {
			http.Error(w, "接続先を確認できません。", 400)
			return
		}
		limit := int64(64 << 10)
		if admin {
			limit = 256 << 10
		}
		if r.ContentLength > limit {
			http.Error(w, "本文が大きすぎます。", 413)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		gate.Wrap(proxy).ServeHTTP(w, r)
	}), nil
}

// sameOriginHost はHTTPS既定portとASCIIの大小文字だけを正規化し、別originを拒否する。
func sameOriginHost(host string, base *url.URL) bool {
	if strings.ContainsAny(host, "/?#@ \t\r\n") || strings.HasSuffix(host, ":") {
		return false
	}
	for _, c := range host {
		if c > 127 {
			return false
		}
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Hostname() == "" {
		return false
	}
	port, expected := u.Port(), base.Port()
	if port == "" {
		port = "443"
	}
	if expected == "" {
		expected = "443"
	}
	return strings.EqualFold(u.Hostname(), base.Hostname()) && port == expected
}

func canonicalPath(r *http.Request) bool {
	if r.URL == nil || !strings.HasPrefix(r.URL.Path, "/") || r.URL.EscapedPath() != r.URL.Path || strings.ContainsAny(r.URL.Path, "\\\x00") || strings.Contains(r.URL.Path, "//") {
		return false
	}
	for _, s := range strings.Split(r.URL.Path, "/") {
		if s == "." || s == ".." {
			return false
		}
	}
	return true
}

// Serve は有界TCP/TLS/HTTPを公開し、取消時に受付と転送を停止する。
func Serve(ctx context.Context, c Config) error {
	base, err := url.Parse(c.Origin)
	if err != nil {
		return err
	}
	upstream, err := url.Parse(c.Upstream)
	if err != nil {
		return err
	}
	client, err := tls.LoadX509KeyPair(c.ClientCert, c.ClientKey)
	if err != nil {
		return err
	}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, MaxConnsPerHost: 64, MaxIdleConns: 64, MaxIdleConnsPerHost: 64, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 10 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: base.Hostname(), Certificates: []tls.Certificate{client}}, DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	defer transport.CloseIdleConnections()
	handler, err := handler(c.Origin, upstream, transport, c.AdminPath)
	if err != nil {
		return err
	}
	if _, err = tls.LoadX509KeyPair(c.ServerCert, c.ServerKey); err != nil {
		return err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		pair, e := tls.LoadX509KeyPair(c.ServerCert, c.ServerKey)
		return &pair, e
	}}, HTTP2: &http.HTTP2Config{MaxConcurrentStreams: 16, MaxReadFrameSize: 16 << 10, MaxReceiveBufferPerConnection: 256 << 10, MaxReceiveBufferPerStream: 64 << 10, WriteByteTimeout: 10 * time.Second}}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	listener, err = delivery.LimitListenerBySource(listener, 256, 16)
	if err != nil {
		return err
	}
	defer listener.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			stop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			server.Shutdown(stop)
		case <-done:
		}
	}()
	err = server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
