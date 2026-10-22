// 署名計画による鍵束の単発/定期巡回を、終了要求とJSON報告へ接続する。
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

// runBackupKeysMaintenance は正本不要のCLI。watchは待機中の終了要求を正常終了する。
func runBackupKeysMaintenance(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var o bootstrap.BackupKeysMaintenanceOptions
	flags.StringVar(&o.KeysParent, "keys-parent", "", "鍵束専用0700親directory（絶対path）")
	flags.StringVar(&o.PlanParent, "plan-parent", "", "name.jsonの署名計画を置く別0700親directory（絶対path）")
	flags.StringVar(&o.TrustInstance, "trust-instance", "", "両親外へ別保管した公開instance file（絶対path）")
	flags.IntVar(&o.Limit, "limit", 16, "一回の組数上限（1〜128）")
	flags.DurationVar(&o.Budget, "budget", 30*time.Second, "一回の時間上限（1秒〜5分）")
	flags.BoolVar(&o.Apply, "apply", false, "認証した期限切れ鍵束を回収し、計画を使用済み化")
	var after string
	if action == "watch-keys-planned" {
		flags.DurationVar(&o.Interval, "interval", time.Minute, "完了後の待機（1分〜24時間）")
	} else {
		flags.StringVar(&after, "after", "", "前回next_after（空なら先頭）")
	}
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || o.KeysParent == "" || o.PlanParent == "" || o.TrustInstance == "" || o.Budget < time.Second || o.Budget > 5*time.Minute {
		return errors.New("planned key sweep/watch requires --keys-parent, --plan-parent, --trust-instance and budget 1s..5m, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	encoder := json.NewEncoder(out)
	if action == "sweep-keys-planned" {
		batch, cancel := context.WithTimeout(ctx, o.Budget)
		defer cancel()
		report, e := bootstrap.SweepPlannedBackupKeys(batch, o.KeysParent, o.PlanParent, o.TrustInstance, after, o.Limit, o.Apply)
		return errors.Join(e, encoder.Encode(report))
	}
	e := bootstrap.RunBackupKeysMaintenance(ctx, o, func(r bootstrap.BackupMaintenanceReport) error { return encoder.Encode(r) })
	if ctx.Err() != nil && e == context.Canceled {
		return nil
	}
	return e
}
