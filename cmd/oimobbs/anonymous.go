// 停止中の匿名Cookie有効化と失効。秘密Cookieを引数・出力へ出さない。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func runAnonymous(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "revoke" && args[0] != "revoke-all") {
		return errors.New("usage: oimobbs anonymous enable|revoke|revoke-all --config <path>")
	}
	flags := flag.NewFlagSet("anonymous "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
	var mode, subject string
	if args[0] == "enable" {
		flags.StringVar(&mode, "mode", "required", "required（全投稿でCookie必須）")
	}
	if args[0] == "revoke" {
		flags.StringVar(&subject, "subject", "", "検証済み主体のHMAC（Cookie原文ではない）")
	}
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	var hash *domain.Hash
	if args[0] == "revoke" {
		var h domain.Hash
		if e := json.Unmarshal([]byte(`"`+subject+`"`), &h); e != nil || h == (domain.Hash{}) {
			return errors.New("invalid subject HMAC")
		}
		hash = &h
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	repo, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	var result any
	if args[0] == "enable" {
		result, e = repo.EnableAnonymous(mode)
	} else {
		e = repo.RevokeAnonymous(hash)
		result = map[string]string{"status": "revoked"}
	}
	e = errors.Join(e, repo.Close())
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
