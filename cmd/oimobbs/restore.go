// 停止中の最新完全正本から、別保存先へ検証付き公開復元を行う。
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

func runRestore(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	sourcePath := flags.String("source-config", "", "停止中の最新正本または本文欠落後の最新台帳側の設定")
	backupPath := flags.String("backup", "", "欠けた本文を補う旧バックアップ（制御情報は使用しない）")
	targetPath := flags.String("config", "", "まだ存在しない復元先の設定")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *sourcePath == "" || *targetPath == "" {
		return errors.New("restore requires --source-config and --config")
	}
	source, e := bootstrap.LoadConfig(*sourcePath)
	if e != nil {
		return e
	}
	target, e := bootstrap.LoadConfig(*targetPath)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var report bootstrap.PublicRestoreReport
	if *backupPath == "" {
		report, e = bootstrap.RestorePublicRepository(ctx, source, target)
	} else {
		report, e = bootstrap.RestorePublicRepositoryFromBackup(ctx, source, target, *backupPath)
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(report)
}
