// 未完成鍵束の計画付き作成/認証回収をCLIの取消・時間上限・失敗JSONへ接続する。
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

// runBackupPartialKeys は作成だけ正本設定を読み、回収にはconfig/秘密鍵を要求しない。
func runBackupPartialKeys(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	input := flags.String("input", "", "本文コピー/未完成鍵束（絶対path）")
	trust := flags.String("trust-instance", "", "別保管公開完了印（絶対file path）")
	plan := flags.String("plan", "", "鍵束外の署名計画（作成時は新規file）")
	var config, output string
	var apply bool
	if action == "export-keys-planned" {
		flags.StringVar(&config, "config", "config.json", "停止中正本設定")
		flags.StringVar(&output, "output", "", "新規0700鍵束（絶対path）")
	} else {
		flags.BoolVar(&apply, "apply", false, "認証した期限切れ未完成鍵束を回収")
	}
	budget := flags.Duration("budget", 30*time.Second, "時間上限（1秒〜5分）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *input == "" || *trust == "" || *plan == "" || (action == "export-keys-planned" && output == "") || *budget < time.Second || *budget > 5*time.Minute {
		return errors.New("partial key backup requires input, trust, plan, new output for export and budget 1s..5m")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var report any
	var e error
	if action == "export-keys-planned" {
		cfg, err := bootstrap.LoadConfig(config)
		if err != nil {
			return err
		}
		report, e = bootstrap.ExportPlannedBackupKeys(ctx, cfg, *input, output, *trust, *plan)
	} else {
		var r bootstrap.BackupReport
		r, e = bootstrap.ReclaimPartialBackupKeys(ctx, *input, *trust, *plan, apply)
		report = r
		if r.ID == (domain.ID{}) {
			report = map[string]bool{"expired": false, "applied": false, "verified": false, "restore_ready": false}
		}
	}
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
