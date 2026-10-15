// 再生作業領域の定期巡回CLIを終了要求と逐次JSON報告へ接続する。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"oimobbs/internal/bootstrap"
)

// runBackupReplayMaintenance は設定不要の独立プロセスを起動し、SIGINT/SIGTERMで正常終了する。
func runBackupReplayMaintenance(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup watch-replay", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var o bootstrap.ReplayMaintenanceOptions
	var cleanupKey string
	flags.StringVar(&o.WorkParent, "work-parent", "", "専用0700作業親directory（絶対path）")
	flags.StringVar(&o.Keys, "keys", "", "対応する別保管鍵bundle（絶対path）")
	flags.StringVar(&cleanupKey, "cleanup-key", "", "事前保存した独立回収鍵（keysとは排他）")
	flags.IntVar(&o.Limit, "limit", 16, "一回の領域上限（1〜128）")
	flags.DurationVar(&o.Interval, "interval", time.Minute, "完了後の待機（1分〜24時間）")
	flags.DurationVar(&o.Budget, "budget", 30*time.Second, "一回の時間上限（1秒〜5分）")
	flags.BoolVar(&o.Apply, "apply", false, "認証済みの停止領域を定期回収")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || o.WorkParent == "" || (o.Keys == "") == (cleanupKey == "") {
		return errors.New("backup watch-replay requires --work-parent and exactly one of --keys or --cleanup-key, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	emit := func(report bootstrap.ReplayMaintenanceReport) error { return encoder.Encode(report) }
	var e error
	if cleanupKey != "" {
		o.Keys = cleanupKey
		e = bootstrap.RunIndependentReplayMaintenance(ctx, o, emit)
	} else {
		e = bootstrap.RunBackupReplayMaintenance(ctx, o, emit)
	}
	if ctx.Err() != nil && e == context.Canceled {
		return nil
	}
	return e
}
