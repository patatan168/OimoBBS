// 停止中バックアップの捕捉・認証照合・期限切れ回収をCLIへ接続する。
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
)

func runBackup(args []string, out, diagnostics io.Writer) error {
	if len(args) > 0 && args[0] == "sweep-online" {
		return runOnlineBackupCleanup(args[1:], out, diagnostics)
	}
	if len(args) == 0 {
		return errors.New("usage: backup sweep-online | prepare | capture | verify | reclaim | reclaim-keys | export-keys | verify-with-keys | verify-replay | reclaim-replay | sweep-replay | watch-replay | sweep-expired | watch-expired | export-trust | plan-keys | reclaim-keys-planned | sweep-keys-planned | watch-keys-planned | reclaim-with-keys | capture-planned | reclaim-partial | export-keys-planned | reclaim-keys-partial | sweep-partial | watch-partial | plan-pair | reclaim-pair | sweep-pairs | watch-pairs | prepare-next | watch-prepare")
	}
	if args[0] == "init-replay-cleanup-key" {
		return runReplayCleanupKey(args[1:], out, diagnostics)
	}
	if args[0] == "prepare-next" || args[0] == "watch-prepare" {
		return runBackupPreparationMaintenance(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "sweep-pairs" || args[0] == "watch-pairs" {
		return runBackupPairMaintenance(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "plan-pair" || args[0] == "reclaim-pair" {
		return runBackupPair(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "sweep-partial" || args[0] == "watch-partial" {
		return runBackupPartialMaintenance(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "export-keys-planned" || args[0] == "reclaim-keys-partial" {
		return runBackupPartialKeys(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "capture-planned" || args[0] == "reclaim-partial" {
		return runBackupPartial(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "sweep-keys-planned" || args[0] == "watch-keys-planned" {
		return runBackupKeysMaintenance(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "export-trust" || args[0] == "plan-keys" || args[0] == "reclaim-keys-planned" {
		return runBackupKeysPlan(args[0], args[1:], out, diagnostics)
	}
	if args[0] == "reclaim-replay" {
		return runBackupReplayCleanup(args[1:], out, diagnostics)
	}
	if args[0] == "prepare" {
		return runBackupPrepare(args[1:], out, diagnostics)
	}
	if args[0] == "sweep-replay" {
		return runBackupReplaySweep(args[1:], out, diagnostics)
	}
	if args[0] == "sweep-expired" {
		return runBackupExpiredSweep(args[1:], out, diagnostics)
	}
	if args[0] == "watch-expired" {
		return runBackupExpiredMaintenance(args[1:], out, diagnostics)
	}
	if args[0] == "watch-replay" {
		return runBackupReplayMaintenance(args[1:], out, diagnostics)
	}
	if args[0] == "verify-with-keys" || args[0] == "verify-replay" || args[0] == "reclaim-with-keys" {
		return runBackupKeyVerification(args[0], args[1:], out, diagnostics)
	}
	if args[0] != "capture" && args[0] != "verify" && args[0] != "reclaim" && args[0] != "export-keys" && args[0] != "reclaim-keys" {
		return errors.New("usage: backup capture --output <directory> | verify/reclaim --input <directory> [--apply] | export-keys --input <directory> --output <directory> --config <path>")
	}
	action := args[0]
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定")
	var path, output string
	if action == "capture" {
		flags.StringVar(&path, "output", "", "データ領域外の新規0700コピー先（絶対path）")
	} else {
		flags.StringVar(&path, "input", "", "検査するバックアップ（絶対path）")
	}
	if action == "export-keys" {
		flags.StringVar(&output, "output", "", "コピーとは別領域の新規鍵保管先（絶対path）")
	}
	apply := false
	if action == "reclaim" || action == "reclaim-keys" {
		flags.BoolVar(&apply, "apply", false, "期限切れコピーを回収")
	}
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || path == "" || action == "export-keys" && output == "" {
		return errors.New("backup requires an absolute input/output directory and no positional arguments")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	var report bootstrap.BackupReport
	switch action {
	case "capture":
		report, e = bootstrap.CaptureOfflineBackup(context.Background(), cfg, path)
	case "verify":
		report, e = bootstrap.VerifyOfflineBackup(context.Background(), cfg, path)
	case "reclaim-keys":
		report, e = bootstrap.ReclaimBackupKeys(context.Background(), cfg, path, apply)
	case "export-keys":
		report, e = bootstrap.ExportBackupKeys(context.Background(), cfg, path, output)
	case "reclaim":
		report, e = bootstrap.ReclaimOfflineBackup(context.Background(), cfg, path, apply)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(report)
}

// runBackupKeyVerification は正本設定を要求せず、鍵bundleで照合・隔離再生する。
func runBackupKeyVerification(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	input := flags.String("input", "", "検査するバックアップ（絶対path）")
	keys := flags.String("keys", "", "別保管した鍵bundle（絶対path）")
	apply := false
	if action == "reclaim-with-keys" {
		flags.BoolVar(&apply, "apply", false, "期限切れ本文コピーを回収（鍵bundleは保持）")
	}
	var workParent, cleanupKey string
	if action == "verify-replay" {
		flags.StringVar(&workParent, "work-parent", "", "隔離作業用の0700親directory（絶対path）")
		flags.StringVar(&cleanupKey, "cleanup-key", "", "事前作成した独立回収鍵（省略可）")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || *keys == "" || action == "verify-replay" && workParent == "" {
		return errors.New("backup key verification requires --input, --keys and (for replay) --work-parent, without config")
	}
	var report bootstrap.BackupReport
	var err error
	if action == "verify-replay" || action == "reclaim-with-keys" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if action == "verify-replay" {
			if cleanupKey != "" {
				report, err = bootstrap.VerifyBackupReplayWithCleanupKey(ctx, *input, *keys, workParent, cleanupKey)
			} else {
				report, err = bootstrap.VerifyBackupReplay(ctx, *input, *keys, workParent)
			}
		} else {
			report, err = bootstrap.ReclaimBackupWithKeys(ctx, *input, *keys, apply)
		}
	} else {
		report, err = bootstrap.VerifyBackupWithKeys(context.Background(), *input, *keys)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
