// 停止中の監査移管照合を提供する。証明が最新でない場合もJSONで未完了を明示する。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
)

func runAudit(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || (args[0] != "verify-transfer" && args[0] != "prepare-retention" && args[0] != "verify-retention" && args[0] != "apply-retention" && args[0] != "reclaim-days") {
		return errors.New("usage: oimobbs audit reclaim-days --config <path> [--apply], audit apply-retention --config <path> --input <absolute directory>, audit verify-transfer --config <path>, audit prepare-retention --config <path> --output <absolute directory>, audit verify-retention --config <path> --input <absolute directory>")
	}
	flags := flag.NewFlagSet("audit "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
	var path string
	apply := false
	if args[0] == "reclaim-days" {
		flags.BoolVar(&apply, "apply", false, "期限切れの日別監査を回収（既定は対象表示）")
	} else if args[0] == "prepare-retention" {
		flags.StringVar(&path, "output", "", "新規更新候補ディレクトリ")
	} else if args[0] == "verify-retention" || args[0] == "apply-retention" {
		flags.StringVar(&path, "input", "", "更新候補ディレクトリ")
	}
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (args[0] != "verify-transfer" && args[0] != "reclaim-days" && path == "") {
		return errors.New("unexpected positional arguments")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	if args[0] == "reclaim-days" {
		report, err := bootstrap.ReclaimAuditDays(context.Background(), cfg, apply, postcapture.Validate)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	if args[0] == "apply-retention" {
		report, err := bootstrap.ApplyAuditRetention(context.Background(), cfg, path, postcapture.Validate)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	if args[0] != "verify-transfer" {
		var report bootstrap.AuditRetentionReport
		if args[0] == "prepare-retention" {
			report, e = repo.PrepareAuditRetention(context.Background(), path)
		} else {
			report, e = repo.VerifyAuditRetention(context.Background(), path)
		}
		e = errors.Join(e, repo.Close())
		if e != nil {
			return e
		}
		return json.NewEncoder(out).Encode(report)
	}
	report, e := repo.VerifyAuditTransfer(context.Background())
	e = errors.Join(e, repo.Close())
	if e != nil {
		return e
	}
	if e = json.NewEncoder(out).Encode(report); e != nil {
		return e
	}
	if !report.Complete {
		return errors.New("監査の移管が最新の確定seqまで完了していません")
	}
	return nil
}
