// 既存サイトだけを直結HTTPSで公開する。初期化・板作成は別の明示CLI操作で行う。
package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func runServe(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("config", "config.json", "起動用設定JSON")
	backupPath := flags.String("online-backup-config", "", "定期オンラインbackupの所有者限定設定JSON（省略可）")
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
	var backups *bootstrap.OnlineBackupConfig
	if *backupPath != "" {
		value, e := bootstrap.LoadOnlineBackupConfig(*backupPath, cfg)
		if e != nil {
			return e
		}
		backups = &value
	}
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalContext)
	defer cancel()
	done := make(chan struct{})
	defer close(done)
	// Sync/所有列が戻らない場合も30秒でprocessを終了し、結果不明の操作は次の起動で裁定する。
	go publicShutdownDeadline(ctx, done, 30*time.Second, func() { os.Exit(1) })
	return serveConfigured(ctx, cfg, false, "", "", "", out, true, backups, true, cancel)
}

func publicShutdownDeadline(ctx context.Context, done <-chan struct{}, duration time.Duration, expired func()) {
	select {
	case <-done:
		return
	case <-ctx.Done():
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-done:
		return
	case <-timer.C:
		expired()
	}
}
