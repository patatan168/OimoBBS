// バックアップ作成から別保管鍵・隔離再生までを一括実行し、部分結果も報告する。
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

// runBackupPrepare は終了要求と全工程の時間上限を接続する。
func runBackupPrepare(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup prepare", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定")
	output := flags.String("output", "", "新規本文コピー先（絶対path）")
	keys := flags.String("keys-output", "", "新規の別保管鍵束先（絶対path）")
	work := flags.String("work-parent", "", "既存0700の隔離再生作業親（絶対path）")
	trust := flags.String("trust-instance", "", "任意の別保管公開完了印（計画と対で指定）")
	partialPlan := flags.String("partial-plan", "", "本文外の新規署名計画file（絶対path）")
	keysPlan := flags.String("partial-keys-plan", "", "鍵束外の新規事前署名計画（本文計画と併用）")
	completePlan := flags.String("keys-plan", "", "鍵束外の新規完成鍵束回収計画（絶対path）")
	pairPlan := flags.String("pair-plan", "", "本文/鍵束外の新規完成ペア回収計画（絶対path）")
	budget := flags.Duration("budget", 5*time.Minute, "全工程の時間上限（1秒〜1時間）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	hasPlan := *partialPlan != "" || *keysPlan != "" || (*completePlan != "" || *pairPlan != "")
	if (*keysPlan != "" && *partialPlan == "") || (*trust != "") != hasPlan || flags.NArg() != 0 || *output == "" || *keys == "" || *work == "" || *budget < time.Second || *budget > time.Hour {
		return errors.New("backup prepare requires --output, --keys-output, --work-parent and budget 1s..1h; --trust-instance requires a plan; --partial-keys-plan requires --partial-plan")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var report bootstrap.BackupPreparationReport
	if *completePlan != "" || *pairPlan != "" {
		report, e = bootstrap.PrepareOfflineBackupPlanned(ctx, cfg, *output, *keys, *work, bootstrap.BackupPreparationPlans{TrustInstance: *trust, PartialPlan: *partialPlan, PartialKeysPlan: *keysPlan, KeysPlan: *completePlan, PairPlan: *pairPlan})
	} else if *keysPlan != "" {
		report, e = bootstrap.PrepareOfflineBackupWithPlans(ctx, cfg, *output, *keys, *work, *trust, *partialPlan, *keysPlan)
	} else if *partialPlan != "" {
		report, e = bootstrap.PreparePlannedOfflineBackup(ctx, cfg, *output, *keys, *work, *trust, *partialPlan)
	} else {
		report, e = bootstrap.PrepareOfflineBackup(ctx, cfg, *output, *keys, *work)
	}
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
