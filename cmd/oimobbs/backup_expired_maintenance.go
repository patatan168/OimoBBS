// 本文期限の定期巡回CLIを終了要求と一巡回一行のJSON報告へ接続する。
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

// runBackupExpiredMaintenance は正本不要の独立プロセスをSIGINT/SIGTERMで正常終了する。
func runBackupExpiredMaintenance(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup watch-expired", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var o bootstrap.BackupMaintenanceOptions
	flags.StringVar(&o.CopyParent, "copy-parent", "", "本文コピー専用0700親directory（絶対path）")
	flags.StringVar(&o.KeysParent, "keys-parent", "", "同名の別保管鍵束を置く0700親directory（絶対path）")
	flags.IntVar(&o.Limit, "limit", 16, "一回の組数上限（1〜128）")
	flags.DurationVar(&o.Interval, "interval", time.Minute, "完了後の待機（1分〜24時間）")
	flags.DurationVar(&o.Budget, "budget", 30*time.Second, "一回の時間上限（1秒〜5分）")
	flags.BoolVar(&o.Apply, "apply", false, "認証した期限切れ本文を定期回収（鍵束は保持）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || o.CopyParent == "" || o.KeysParent == "" {
		return errors.New("backup watch-expired requires --copy-parent and --keys-parent, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	e := bootstrap.RunBackupMaintenance(ctx, o, func(r bootstrap.BackupMaintenanceReport) error { return encoder.Encode(r) })
	if ctx.Err() != nil && e == context.Canceled {
		return nil
	}
	return e
}
