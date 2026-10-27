// 対応する本文/鍵束の親を指定する期限切れ巡回CLI。失敗時にも部分結果を出力する。
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

func runBackupExpiredSweep(args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("backup sweep-expired", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	copies := flags.String("copy-parent", "", "本文コピー専用0700親directory（絶対path）")
	keys := flags.String("keys-parent", "", "同名の鍵束を保管する別0700親directory（絶対path）")
	after := flags.String("after", "", "前回next_after（空なら先頭）")
	limit := flags.Int("limit", 16, "一回に検査する組数（1〜128）")
	budget := flags.Duration("budget", 30*time.Second, "時間上限（1秒〜5分）")
	apply := flags.Bool("apply", false, "認証した期限切れ本文を回収（鍵束は保持）")
	if e := flags.Parse(args); e != nil {
		return e
	}
	if flags.NArg() != 0 || *copies == "" || *keys == "" || *budget < time.Second || *budget > 5*time.Minute {
		return errors.New("backup sweep-expired requires --copy-parent, --keys-parent and budget 1s..5m, without config")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	report, e := bootstrap.SweepExpiredBackups(ctx, *copies, *keys, *after, *limit, *apply)
	return errors.Join(e, json.NewEncoder(out).Encode(report))
}
