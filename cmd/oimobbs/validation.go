// 永続データを持つ検証用サーバーの起動・終了とコンテナの生存確認を提供する。
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/delivery"
	"oimobbs/internal/postcapture"
)

func runValidation(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("validation-serve", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("config", "config.json", "検証用設定JSON")
	backupConfig := flags.String("online-backup-config", "", "定期オンラインバックアップの所有者限定設定JSON（省略可）")
	admin := flags.Bool("admin", false, "設定済みの管理HTTP/HTTPSリスナーも起動")
	initialize := flags.Bool("init-if-missing", false, "保存先が存在しない場合だけ初期化")
	name := flags.String("name", "OimoBBS 検証環境", "初期サイト名")
	board := flags.String("board-key", "", "起動時に用意する検証板（省略可）")
	boardName := flags.String("board-name", "検証板", "検証板の表示名")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := bootstrap.LoadConfig(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var backups *bootstrap.OnlineBackupConfig
	if *backupConfig != "" {
		loaded, e := bootstrap.LoadOnlineBackupConfig(*backupConfig, cfg)
		if e != nil {
			return e
		}
		backups = &loaded
	}
	return serveValidationWithBackups(ctx, cfg, *initialize, *name, *board, *boardName, out, *admin, backups)
}

func serveValidation(ctx context.Context, cfg bootstrap.Config, initialize bool, name, board, boardName string, out io.Writer, enableAdmin ...bool) (resultErr error) {
	admin := len(enableAdmin) > 0 && enableAdmin[0]
	return serveValidationWithBackups(ctx, cfg, initialize, name, board, boardName, out, admin, nil)
}

func serveValidationWithBackups(ctx context.Context, cfg bootstrap.Config, initialize bool, name, board, boardName string, out io.Writer, enableAdmin bool, backups *bootstrap.OnlineBackupConfig) (resultErr error) {
	return serveConfigured(ctx, cfg, initialize, name, board, boardName, out, enableAdmin, backups, false)
}

// serveConfigured は起動検査・全リスナー確保・保守・期限掃除・終了を共有する。
func serveConfigured(ctx context.Context, cfg bootstrap.Config, initialize bool, name, board, boardName string, out io.Writer, enableAdmin bool, backups *bootstrap.OnlineBackupConfig, production bool, shutdownStarted ...func()) error {
	return serveConfiguredWithNetworkClient(ctx, cfg, initialize, name, board, boardName, out, enableAdmin, backups, production, nil, shutdownStarted...)
}

// serveConfiguredWithNetworkClient は初回取得の通信を差し替えて実サーバーの起動を検証する。
func serveConfiguredWithNetworkClient(ctx context.Context, cfg bootstrap.Config, initialize bool, name, board, boardName string, out io.Writer, enableAdmin bool, backups *bootstrap.OnlineBackupConfig, production bool, networkClient *http.Client, shutdownStarted ...func()) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if production && !strings.HasPrefix(cfg.Public.BaseURL, "https://") {
		return errors.New("public serve requires direct HTTPS")
	}
	out = &validationOutput{writer: out}
	if _, err := os.Lstat(cfg.DataDir); errors.Is(err, os.ErrNotExist) && initialize {
		if _, err = bootstrap.Initialize(cfg, name); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	repo, err := bootstrap.OpenPostingRepository(cfg, postcapture.Validate, bootstrap.PostingOptions{ParallelCaptureValidation: true})
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, repo.Close()) }()
	if board != "" {
		if _, err = repo.CreateBoard(ctx, board, boardName); err != nil {
			return err
		}
	}
	if production {
		if err = repo.ValidatePublicPrerequisites(); err != nil {
			return err
		}
	}
	if err = repo.EnsureStandardNetworks(networkClient); err != nil {
		return err
	}
	if err = repo.EnableSlip(); err != nil {
		return err
	}
	if err = repo.ValidatePackMaintenance(); err != nil {
		return err
	}
	if err = repo.EnableThreadRetention(ctx); err != nil {
		return err
	}
	if production {
		if err = repo.EnableStoragePressureReclamation(ctx); err != nil {
			return err
		}
		if err = repo.TransferThreadAudits(ctx, 8); err != nil {
			return err
		}
	}
	if err = repo.EnableControlExpiry(ctx); err != nil {
		return err
	}
	if _, err = repo.SweepExpiredControl(ctx, 128); err != nil {
		return err
	}
	var server *http.Server
	if production {
		server, err = repo.PublicHTTPServer()
	} else {
		server, err = repo.ValidationHTTPServer()
	}
	if err != nil {
		return err
	}
	socket, err := net.Listen("tcp", cfg.Public.Listen)
	if err != nil {
		return err
	}
	socket, err = limitPublicListener(socket, cfg)
	if err != nil {
		return err
	}
	defer socket.Close()
	defer server.Close()
	var adminServer *http.Server
	var adminSocket net.Listener
	if enableAdmin && cfg.Admin.Transport != "public_path" {
		adminServer, err = repo.AdminHTTPServer()
		if err != nil {
			return err
		}
		adminSocket, err = net.Listen("tcp", cfg.Admin.Listen)
		if err != nil {
			return err
		}
		if cfg.Admin.Transport == "direct_https" {
			adminSocket, err = delivery.LimitListenerBySource(adminSocket, 64, 8)
		} else {
			adminSocket, err = delivery.LimitListener(adminSocket, 64)
		}
		if err != nil {
			return err
		}
		defer adminSocket.Close()
		defer adminServer.Close()
	}
	maintenanceContext, stopMaintenance := context.WithCancel(ctx)
	expiryDone := make(chan struct{})
	var expiryErr error
	go func() { expiryErr = repo.RunControlExpiryMaintenance(maintenanceContext); close(expiryDone) }()
	defer func() {
		stopMaintenance()
		<-expiryDone
		if !errors.Is(expiryErr, context.Canceled) {
			resultErr = errors.Join(resultErr, expiryErr)
		}
	}()
	storageDone := make(chan struct{})
	go func() { repo.RunStorageMonitor(maintenanceContext); close(storageDone) }()
	defer func() { stopMaintenance(); <-storageDone }()
	maintenanceDone := make(chan struct{})
	var maintenanceErr error
	go func() { maintenanceErr = repo.RunPackMaintenance(maintenanceContext); close(maintenanceDone) }()
	defer func() { stopMaintenance(); <-maintenanceDone; resultErr = errors.Join(resultErr, maintenanceErr) }()
	backupDone := make(chan struct{})
	var backupErr error
	if backups != nil {
		options, capture := backups.Options()
		go func() {
			backupErr = repo.RunOnlineBackupMaintenance(maintenanceContext, options, capture, func(report bootstrap.BackupPreparationMaintenanceReport) error {
				return json.NewEncoder(out).Encode(report)
			})
			close(backupDone)
		}()
		defer func() {
			stopMaintenance()
			<-backupDone
			if !errors.Is(backupErr, context.Canceled) {
				resultErr = errors.Join(resultErr, backupErr)
			}
		}()
	}
	done := make(chan error, 2)
	if adminServer != nil {
		go func() {
			if cfg.Admin.Transport == "direct_https" {
				done <- adminServer.ServeTLS(adminSocket, "", "")
			} else {
				done <- adminServer.Serve(adminSocket)
			}
		}()
		fmt.Fprintln(out, "管理画面:", cfg.Admin.Origin)
	}
	go func() {
		if cfg.Public.TLSCert != "" {
			done <- server.ServeTLS(socket, "", "")
		} else {
			done <- server.Serve(socket)
		}
	}()
	if production {
		fmt.Fprintln(out, "公開サーバー:", cfg.Public.BaseURL, "（直結HTTPS）")
	} else {
		fmt.Fprintln(out, "検証用サーバー:", cfg.Public.BaseURL, "（板・投稿は永続保存。公開運用はserveを使用）")
	}
	select {
	case err = <-done:
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	case <-maintenanceDone:
	case <-expiryDone:
	case <-backupDone:
	case <-ctx.Done():
	}
	for _, started := range shutdownStarted {
		started()
	}
	stopMaintenance()
	shutdown, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	err = errors.Join(err, server.Shutdown(shutdown))
	if adminServer != nil {
		err = errors.Join(err, adminServer.Shutdown(shutdown))
	}
	return err
}

func runHealthcheck(args []string, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("config", "config.json", "起動設定JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := bootstrap.LoadConfig(*path)
	if err != nil {
		return err
	}
	host, port, err := net.SplitHostPort(cfg.Public.Listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, net.JoinHostPort(host, port))
	}}
	defer transport.CloseIdleConnections()
	if cfg.Edge != nil {
		transport.DialContext = nil
	} // 認証edgeを迂回せず、公開originの通常利用者経路を確認する。
	if cfg.Public.TLSCert != "" {
		cert, err := os.ReadFile(cfg.Public.TLSCert)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if cfg.Edge != nil {
			if system, e := x509.SystemCertPool(); e == nil {
				roots = system
			}
		}
		if !roots.AppendCertsFromPEM(cert) {
			return errors.New("invalid healthcheck certificate")
		}
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(cfg.Public.BaseURL + "/")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("healthcheck: HTTP %d", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, response.Body)
	return err
}

// validationOutput は起動ログと定期作成JSONの並行書込みを直列化する。
type validationOutput struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *validationOutput) Write(raw []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.writer.Write(raw)
}
