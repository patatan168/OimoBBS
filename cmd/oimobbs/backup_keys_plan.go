// 公開信頼根の別保管・鍵回収計画・正本なし回収を時間上限と失敗JSONへ接続する。
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

func runBackupKeysPlan(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	var config, input, trust, output, plan string
	var apply bool
	if action != "reclaim-keys-planned" {
		flags.StringVar(&config, "config", "config.json", "停止中の正本設定")
	}
	if action == "export-trust" || action == "plan-keys" {
		flags.StringVar(&output, "output", "", "別領域の新規0600file（絶対path）")
	}
	if action != "export-trust" {
		flags.StringVar(&input, "input", "", "対象の鍵束directory（絶対path）")
		flags.StringVar(&trust, "trust-instance", "", "別保管した公開完了印（絶対file path）")
	}
	if action == "reclaim-keys-planned" {
		flags.StringVar(&plan, "plan", "", "外部署名計画（絶対file path）")
		flags.BoolVar(&apply, "apply", false, "認証した期限切れ鍵束を回収（計画と信頼根は保持）")
	}
	budget := flags.Duration("budget", 30*time.Second, "時間上限（1秒〜5分）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *budget < time.Second || *budget > 5*time.Minute || action == "export-trust" && output == "" || action == "plan-keys" && (input == "" || trust == "" || output == "") || action == "reclaim-keys-planned" && (input == "" || trust == "" || plan == "") {
		return errors.New("backup key plan requires input/output/trust/plan flags appropriate to action and budget 1s..5m")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	var cfg bootstrap.Config
	var e error
	if action != "reclaim-keys-planned" {
		cfg, e = bootstrap.LoadConfig(config)
		if e != nil {
			return e
		}
	}
	var report any
	switch action {
	case "export-trust":
		report, e = bootstrap.ExportBackupTrust(ctx, cfg, output)
	case "plan-keys":
		report, e = bootstrap.PlanBackupKeysReclamation(ctx, cfg, input, trust, output)
	case "reclaim-keys-planned":
		var reclaimed bootstrap.BackupReport
		reclaimed, e = bootstrap.ReclaimBackupKeysPlanned(ctx, input, trust, plan, apply)
		report = reclaimed
		if reclaimed.ID == (domain.ID{}) {
			report = map[string]bool{"expired": false, "applied": false, "verified": false, "restore_ready": false}
		}
	}
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
