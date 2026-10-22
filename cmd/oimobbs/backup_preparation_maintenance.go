// 停止中の新規バックアップ作成/定期実行をCLIへ接続し、既定は確認のみにする。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// runBackupPreparationMaintenance は固定親と公開信頼根を読み、apply時だけ4計画付き作成を行う。
func runBackupPreparationMaintenance(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中正本の設定（起動時だけ読込）")
	var o bootstrap.BackupPreparationMaintenanceOptions
	flags.StringVar(&o.CopyParent, "copy-parent", "", "本文専用0700親")
	flags.StringVar(&o.KeysParent, "keys-parent", "", "鍵束専用0700親")
	flags.StringVar(&o.PartialPlanParent, "partial-plan-parent", "", "本文事前計画専用0700親")
	flags.StringVar(&o.PartialKeysPlanParent, "partial-keys-plan-parent", "", "鍵束事前計画専用0700親")
	flags.StringVar(&o.KeysPlanParent, "keys-plan-parent", "", "完成鍵束計画専用0700親")
	flags.StringVar(&o.PairPlanParent, "pair-plan-parent", "", "完成ペア計画専用0700親")
	flags.StringVar(&o.WorkParent, "work-parent", "", "隔離再生専用0700親")
	flags.StringVar(&o.ControlParent, "control-parent", "", "定期作成排他専用0700親")
	flags.StringVar(&o.TrustInstance, "trust-instance", "", "全親/正本外の公開信頼根")
	flags.DurationVar(&o.Budget, "budget", 5*time.Minute, "全工程上限（1秒〜1時間）")
	flags.BoolVar(&o.Apply, "apply", false, "新規本文/鍵束/4計画を作成して隔離再生")
	if action == "watch-prepare" {
		flags.DurationVar(&o.Interval, "interval", time.Hour, "完了後の待機（1〜24時間）")
	}
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("preparation maintenance does not accept positional arguments")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	if action == "prepare-next" {
		report, e := bootstrap.PrepareNextOfflineBackup(ctx, cfg, o)
		return errors.Join(e, encoder.Encode(report))
	}
	e = bootstrap.RunBackupPreparationMaintenance(ctx, cfg, o, func(r bootstrap.BackupPreparationMaintenanceReport) error { return encoder.Encode(r) })
	if ctx.Err() != nil && e == context.Canceled {
		return nil
	}
	return e
}
