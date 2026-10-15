// 正本設定なしの再生領域回収をCLIへ接続し、終了要求をpayload境界で中断する。
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

func runBackupReplayCleanup(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup reclaim-replay", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	input := flags.String("input", "", "停止した検証作業root（絶対path）")
	keys := flags.String("keys", "", "対応する別保管鍵bundle（絶対path）")
	cleanupKey := flags.String("cleanup-key", "", "事前保存した独立回収鍵（keysとは排他）")
	apply := flags.Bool("apply", false, "認証済みの停止領域を回収")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *input == "" || (*keys == "") == (*cleanupKey == "") {
		return errors.New("backup reclaim-replay requires --input and exactly one of --keys or --cleanup-key, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var report bootstrap.ReplayReclaimReport
	var e error
	if *cleanupKey != "" {
		report, e = bootstrap.ReclaimBackupReplayWithCleanupKey(ctx, *input, *cleanupKey, *apply)
	} else {
		report, e = bootstrap.ReclaimBackupReplay(ctx, *input, *keys, *apply)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(report)
}

// runReplayCleanupKey は既存鍵を上書きせず、独立回収用の鍵だけを生成する。
func runReplayCleanupKey(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup init-replay-cleanup-key", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("output", "", "別保管する新規0600回収鍵（絶対path）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *path == "" {
		return errors.New("cleanup key initialization requires --output")
	}
	if e := bootstrap.InitializeReplayCleanupKey(*path); e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(map[string]bool{"created": true, "restore_ready": false})
}
