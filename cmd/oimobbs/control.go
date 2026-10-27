// 停止中のサイトについて、監査検証済みcontrol snapshot候補を作成・照合する。
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

func runControl(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || (args[0] != "prepare-snapshot" && args[0] != "verify-snapshot" && args[0] != "enable-snapshots" && args[0] != "activate-snapshot" && args[0] != "reclaim-wal") {
		return errors.New("usage: oimobbs control reclaim-wal --config <path> [--apply], control enable-snapshots --config <path>, control activate-snapshot --config <path> --input <absolute directory>, control prepare-snapshot --config <path> --output <absolute directory> [--level 0|1|6|9], or control verify-snapshot --config <path> --input <absolute directory>")
	}
	flags := flag.NewFlagSet("control "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
	var path string
	level := 6
	apply := false
	if args[0] == "prepare-snapshot" {
		flags.StringVar(&path, "output", "", "新規候補ディレクトリ（データ領域外の絶対path）")
		flags.IntVar(&level, "level", 6, "0=raw、gzip=1/6/9")
	} else if args[0] == "reclaim-wal" {
		flags.BoolVar(&apply, "apply", false, "照合済みの旧WALを削除（既定は対象表示のみ）")
	} else if args[0] != "enable-snapshots" {
		flags.StringVar(&path, "input", "", "検査する候補ディレクトリの絶対path")
	}
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 || (path == "" && args[0] != "enable-snapshots" && args[0] != "reclaim-wal") {
		return errors.New("a candidate directory is required; positional arguments are not allowed")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	if args[0] == "reclaim-wal" {
		report, err := bootstrap.ReclaimControlWAL(context.Background(), cfg, apply, postcapture.Validate)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	if args[0] == "activate-snapshot" {
		report, err := bootstrap.ActivateControlSnapshot(context.Background(), cfg, path, postcapture.Validate)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	var report any
	if args[0] == "enable-snapshots" {
		report, e = repo.EnableControlSnapshots(context.Background())
	} else if args[0] == "prepare-snapshot" {
		report, e = repo.PrepareControlSnapshot(context.Background(), path, level)
	} else {
		report, e = repo.VerifyControlSnapshot(context.Background(), path)
	}
	e = errors.Join(e, repo.Close())
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(report)
}
