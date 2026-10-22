// 計画付き停止中コピーと未完成出力の認証回収を、時間上限と失敗JSONへ接続する。
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
	"oimobbs/internal/domain"
)

// runBackupPartial はcaptureだけ正本設定を使い、回収は公開信頼根と計画だけを使う。
func runBackupPartial(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var config, path string
	if action == "capture-planned" {
		flags.StringVar(&config, "config", "config.json", "停止中の正本設定")
		flags.StringVar(&path, "output", "", "新規0700コピー先（絶対path）")
	} else {
		flags.StringVar(&path, "input", "", "計画に対応する未完成コピー（絶対path）")
	}
	trust := flags.String("trust-instance", "", "別保管公開完了印（絶対file path）")
	plan := flags.String("plan", "", "コピー外の署名計画（captureは新規file、絶対path）")
	apply := false
	if action == "reclaim-partial" {
		flags.BoolVar(&apply, "apply", false, "認証した期限切れ未完成コピーを回収")
	}
	budget := flags.Duration("budget", 30*time.Second, "時間上限（1秒〜5分）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || path == "" || *trust == "" || *plan == "" || *budget < time.Second || *budget > 5*time.Minute {
		return errors.New("planned capture/partial reclaim requires output/input, --trust-instance, --plan and budget 1s..5m")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var report any
	var e error
	if action == "capture-planned" {
		cfg, err := bootstrap.LoadConfig(config)
		if err != nil {
			return err
		}
		report, e = bootstrap.CapturePlannedOfflineBackup(ctx, cfg, path, *trust, *plan)
	} else {
		var reclaimed bootstrap.BackupReport
		reclaimed, e = bootstrap.ReclaimPartialBackup(ctx, path, *trust, *plan, apply)
		report = reclaimed
		if reclaimed.ID == (domain.ID{}) {
			report = map[string]bool{"expired": false, "applied": false, "verified": false, "restore_ready": false}
		}
	}
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
