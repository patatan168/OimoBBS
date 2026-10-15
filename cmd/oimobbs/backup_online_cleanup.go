// 新規捕捉をせず、オンラインbackupの既存署名計画だけを使って期限回収する。
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

	"oimobbs/internal/bootstrap"
)

// runOnlineBackupCleanup は既定で点検だけを行い、明示applyで最大128組を回収する。
// 拒否/途中終了でも取得できた固定結果を出力し、完了と取り違えないようerrorを返す。
func runOnlineBackupCleanup(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup sweep-online", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "サイト設定JSON")
	backupConfig := flags.String("online-backup-config", "", "既存オンラインbackupの所有者限定設定JSON")
	after := flags.String("after", "", "前回のnext_after")
	workAfter := flags.String("work-after", "", "前回のreplay.next_after")
	limit := flags.Int("limit", 128, "一回の処理上限（1..128）")
	apply := flags.Bool("apply", false, "署名済み期限を過ぎたコピーを回収する")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *backupConfig == "" || *limit < 1 || *limit > 128 {
		return errors.New("sweep-online requires --online-backup-config and limit 1..128")
	}
	cfg, err := bootstrap.LoadConfig(*config)
	if err != nil {
		return err
	}
	value, err := bootstrap.LoadOnlineBackupConfig(*backupConfig, cfg)
	if err != nil {
		return err
	}
	options, _ := value.Options()
	signalContext, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, options.Budget)
	defer cancel()
	report, err := bootstrap.SweepOnlineBackupLifecycle(ctx, options, *after, *workAfter, *limit, *apply)
	return errors.Join(err, json.NewEncoder(out).Encode(report))
}
