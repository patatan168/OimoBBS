// 未完成本文/鍵束の署名計画巡回をCLIの時間上限・終了要求・一行JSONへ接続する。
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

// runBackupPartialMaintenance は正本設定を読まず、用途を明示した単発/周期巡回を行う。
func runBackupPartialMaintenance(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var o bootstrap.BackupPartialMaintenanceOptions
	flags.StringVar(&o.Kind, "kind", "", "未完成出力の用途（body/keys、必須）")
	flags.StringVar(&o.RootParent, "root-parent", "", "用途別の出力専用0700親（絶対path）")
	flags.StringVar(&o.PlanParent, "plan-parent", "", "name.jsonの事前計画専用0700親（絶対path）")
	flags.StringVar(&o.TrustInstance, "trust-instance", "", "両親外の公開信頼根（絶対file path）")
	flags.IntVar(&o.Limit, "limit", 16, "一回の組数上限（1〜128）")
	flags.DurationVar(&o.Budget, "budget", 30*time.Second, "一回の時間上限（1秒〜5分）")
	flags.BoolVar(&o.Apply, "apply", false, "認証した期限切れ未完成出力だけ回収")
	var after string
	if action == "watch-partial" {
		flags.DurationVar(&o.Interval, "interval", time.Minute, "完了後の待機（1分〜24時間）")
	} else {
		flags.StringVar(&after, "after", "", "前回next_after（空なら先頭）")
	}
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || (o.Kind != "body" && o.Kind != "keys") || o.RootParent == "" || o.PlanParent == "" || o.TrustInstance == "" || o.Budget < time.Second || o.Budget > 5*time.Minute {
		return errors.New("partial sweep/watch requires --kind body|keys, --root-parent, --plan-parent, --trust-instance and budget 1s..5m, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	if action == "sweep-partial" {
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		defer cancel()
		report, e := bootstrap.SweepPartialBackups(batch, o.Kind, o.RootParent, o.PlanParent, o.TrustInstance, after, o.Limit, o.Apply)
		result := struct {
			Kind string `json:"kind"`
			bootstrap.BackupSweepReport
		}{o.Kind, report}
		return errors.Join(e, encoder.Encode(result))
	}
	e := bootstrap.RunBackupPartialMaintenance(ctx, o, func(report bootstrap.BackupMaintenanceReport) error {
		result := struct {
			Kind string `json:"kind"`
			bootstrap.BackupMaintenanceReport
		}{o.Kind, report}
		return encoder.Encode(result)
	})
	if ctx.Err() != nil && e == context.Canceled {
		return nil
	}
	return e
}
