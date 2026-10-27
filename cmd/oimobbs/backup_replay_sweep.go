// 件数・時間上限付きの再生領域巡回CLI。部分成功でも結果をJSONへ出力する。
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

// runBackupReplaySweep は終了要求を接続し、拒否・中断時にも再開位置を出力する。
func runBackupReplaySweep(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup sweep-replay", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	parent := flags.String("work-parent", "", "専用0700作業親directory（絶対path）")
	keys := flags.String("keys", "", "対応する別保管鍵bundle（絶対path）")
	cleanupKey := flags.String("cleanup-key", "", "事前保存した独立回収鍵（keysとは排他）")
	after := flags.String("after", "", "前回のnext_after（空なら先頭）")
	limit := flags.Int("limit", 16, "一回に検査する領域数（1〜128）")
	budget := flags.Duration("budget", 30*time.Second, "時間上限（1秒〜5分）")
	apply := flags.Bool("apply", false, "認証済みの停止領域を回収")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *parent == "" || (*keys == "") == (*cleanupKey == "") || *budget < time.Second || *budget > 5*time.Minute {
		return errors.New("backup sweep-replay requires --work-parent, exactly one of --keys or --cleanup-key and budget 1s..5m, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var report bootstrap.ReplaySweepReport
	var e error
	if *cleanupKey != "" {
		report, e = bootstrap.SweepBackupReplayWithCleanupKey(ctx, *parent, *cleanupKey, *after, *limit, *apply)
	} else {
		report, e = bootstrap.SweepBackupReplay(ctx, *parent, *keys, *after, *limit, *apply)
	}
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
