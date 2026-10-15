// Command compatprobe はP0専ブラ通信試験のためのloopback限定サーバを起動する。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"oimobbs/internal/compatprobe"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

// run は公開・管理の両リスナーの起動成功後にURLを案内する。
func run() error {
	listen := flag.String("listen", "127.0.0.1:9080", "public loopback listen address")
	base := flag.String("base-url", "http://127.0.0.1:9080", "client-visible origin")
	adminListen := flag.String("admin-listen", "127.0.0.1:9081", "admin loopback listen address")
	adminBase := flag.String("admin-base-url", "http://127.0.0.1:9081", "admin browser origin")
	keyFile := flag.String("admin-key-file", "var/compatprobe-admin.key", "owner-only admin key file (created on first start)")
	flag.Parse()
	for _, addr := range []string{*listen, *adminListen} {
		if err := validateListen(addr); err != nil {
			return err
		}
	}
	handler, err := compatprobe.New(*base)
	if err != nil {
		return err
	}
	key, err := loadAdminKey(*keyFile)
	if err != nil {
		return err
	}
	admin, err := handler.AdminHandler(*adminBase, key)
	if err != nil {
		return err
	}
	publicSocket, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer publicSocket.Close()
	adminSocket, err := net.Listen("tcp", *adminListen)
	if err != nil {
		return err
	}
	defer adminSocket.Close()
	publicServer, adminServer := probeHTTPServer(handler), probeHTTPServer(admin)
	defer publicServer.Close()
	defer adminServer.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 2)
	go func() { done <- publicServer.Serve(publicSocket) }()
	go func() { done <- adminServer.Serve(adminSocket) }()
	fmt.Fprintln(os.Stderr, "P0互換試験専用: 板・投稿はメモリ上のみ。終了時に消えます。")
	fmt.Fprintln(os.Stderr, "公開画面:", *base, "管理画面:", *adminBase)
	fmt.Fprintln(os.Stderr, "管理キーは次のファイルを確認してください:", *keyFile)
	select {
	case err = <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		stopped := make(chan error, 2)
		go func() { stopped <- publicServer.Shutdown(shutdown) }()
		go func() { stopped <- adminServer.Shutdown(shutdown) }()
		return errors.Join(<-stopped, <-stopped)
	}
}

func validateListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return fmt.Errorf("compatprobe requires loopback listeners")
	}
	return nil
}
func probeHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
}
