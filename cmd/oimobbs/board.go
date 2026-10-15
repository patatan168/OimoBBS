// 停止中のローカル所有者だけが使う、永続板の作成・一覧・復旧CLI。
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

func runBoard(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: oimobbs board create|list|recover --config <path>")
	}
	action := args[0]
	if action != "create" && action != "list" && action != "recover" {
		return errors.New("unknown board command")
	}
	flags := flag.NewFlagSet("board "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "起動設定JSON")
	posting := flags.Bool("validation", false, "検証サーバーの投稿データも照合して管理する")
	var key, name string
	if action == "create" {
		flags.StringVar(&key, "key", "", "英小文字から始まる板キー")
		flags.StringVar(&name, "name", "", "板の表示名")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if action == "create" && (key == "" || name == "") {
		return errors.New("board create requires --key and --name")
	}
	cfg, err := bootstrap.LoadConfig(*config)
	if err != nil {
		return err
	}
	if action == "list" && !*posting {
		rows, err := bootstrap.ListBoards(cfg)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(rows)
	}
	var repo *bootstrap.Repository
	if *posting {
		repo, err = bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	} else {
		repo, err = bootstrap.OpenRepository(cfg)
	}
	if err != nil {
		return err
	}
	var result any
	if action == "create" {
		result, err = repo.CreateBoard(context.Background(), key, name)
	} else {
		result, err = repo.Boards()
	}
	err = errors.Join(err, repo.Close())
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}
