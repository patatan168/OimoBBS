// 完成ペア巡回/定期回収を正本不要CLI・時間上限・終了要求・一行JSONへ接続する。
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

// runBackupPairMaintenance は署名された同名出力の確認/適用を行う。既定は確認のみ。
func runBackupPairMaintenance(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var o bootstrap.BackupPairMaintenanceOptions
	flags.StringVar(&o.CopyParent, "copy-parent", "", "本文専用0700親（絶対path）")
	flags.StringVar(&o.KeysParent, "keys-parent", "", "鍵束専用0700親（絶対path）")
	flags.StringVar(&o.PlanParent, "plan-parent", "", "ペア計画name.jsonの専用0700親（絶対path）")
	flags.StringVar(&o.TrustInstance, "trust-instance", "", "3親外の公開信頼根（絶対file path）")
	flags.IntVar(&o.Limit, "limit", 16, "一回の組数上限（1〜128）")
	flags.DurationVar(&o.Budget, "budget", 30*time.Second, "一回の時間上限（1秒〜5分）")
	flags.BoolVar(&o.Apply, "apply", false, "登録計画の退役と期限切れ本文→鍵束の回収")
	var after string
	if action == "watch-pairs" {
		flags.DurationVar(&o.Interval, "interval", time.Minute, "完了後の待機（1分〜24時間）")
	} else {
		flags.StringVar(&after, "after", "", "前回next_after（空なら先頭）")
	}
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || o.CopyParent == "" || o.KeysParent == "" || o.PlanParent == "" || o.TrustInstance == "" || o.Budget < time.Second || o.Budget > 5*time.Minute {
		return errors.New("pair sweep/watch requires copy-parent, keys-parent, plan-parent, trust-instance and budget 1s..5m, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	if action == "sweep-pairs" {
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		defer cancel()
		r, e := bootstrap.SweepBackupPairs(batch, o.CopyParent, o.KeysParent, o.PlanParent, o.TrustInstance, after, o.Limit, o.Apply)
		return errors.Join(e, encoder.Encode(r))
	}
	e := bootstrap.RunBackupPairMaintenance(ctx, o, func(r bootstrap.BackupPairMaintenanceReport) error { return encoder.Encode(r) })
	if ctx.Err() != nil && e == context.Canceled {
		return nil
	}
	return e
}
