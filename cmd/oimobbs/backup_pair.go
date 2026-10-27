// 完成ペアの署名計画作成と正本不要の順序付き回収をCLIへ接続する。
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

// runBackupPair は作成だけ設定を読み、回収の取消/時間上限/失敗JSONを管理する。
func runBackupPair(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	body := flags.String("input", "", "完成本文root（絶対path）")
	keys := flags.String("keys", "", "対応する完成鍵束root（絶対path）")
	trust := flags.String("trust-instance", "", "別保管公開完了印（絶対file path）")
	plan := flags.String("plan", "", "root外の完成ペア署名計画（作成時は新規file）")
	budget := flags.Duration("budget", 30*time.Second, "時間上限（1秒〜5分）")
	var related bootstrap.BackupPairRelatedPlans
	var config string
	var apply bool
	if action == "plan-pair" {
		flags.StringVar(&config, "config", "config.json", "停止中正本設定")
		flags.StringVar(&related.PartialPlan, "partial-plan", "", "登録する既存本文部分計画")
		flags.StringVar(&related.PartialKeysPlan, "partial-keys-plan", "", "登録する既存鍵束部分計画")
		flags.StringVar(&related.KeysPlan, "keys-plan", "", "登録する既存完成鍵束計画")
	} else {
		flags.BoolVar(&apply, "apply", false, "期限切れ本文を先に回収してから鍵束を回収")
	}
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *body == "" || *keys == "" || *trust == "" || *plan == "" || *budget < time.Second || *budget > 5*time.Minute {
		return errors.New("backup pair requires input, keys, trust-instance, plan and budget 1s..5m")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var report bootstrap.BackupPairReport
	var e error
	if action == "plan-pair" {
		cfg, err := bootstrap.LoadConfig(config)
		if err != nil {
			return err
		}
		report, e = bootstrap.PlanBackupPairReclamationWithPlans(ctx, cfg, *body, *keys, *trust, *plan, related)
	} else {
		report, e = bootstrap.ReclaimBackupPair(ctx, *body, *keys, *trust, *plan, apply)
	}
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
