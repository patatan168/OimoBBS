// 停止中の保存先で必須原本の周期回収を有効化し、次回serveへ設定を引き継ぐ。
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

// runLogs は耐久readerと進捗設定の保存が完了した場合だけ有効化を報告する。
func runLogs(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || args[0] != "enable-required-gc" {
		return errors.New("usage: oimobbs logs enable-required-gc --config <path>")
	}
	flags := flag.NewFlagSet("logs enable-required-gc", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
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
	r, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	e = r.EnableRequiredOriginalReclamation(context.Background())
	e = errors.Join(e, r.Close())
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(map[string]any{"enabled": true, "required_reader_version": 48})
}
