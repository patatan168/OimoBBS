// 固定規制を停止中に一度だけ有効化する。再実行では開始時刻や履歴をリセットしない。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/postcapture"
)

func runAdmission(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || args[0] != "enable" {
		return errors.New("usage: oimobbs admission enable --config <path>")
	}
	flags := flag.NewFlagSet("admission enable", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイトの起動設定JSON")
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	policy, e := repo.EnableAdmission()
	e = errors.Join(e, repo.Close())
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(policy)
}
