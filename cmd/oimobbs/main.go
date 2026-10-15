// Command oimobbs は永続サイトの初期化・管理・検査とHTTP/HTTPS起動を行う。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"oimobbs/internal/bootstrap"
	"oimobbs/internal/platform"
)

func main() {
	platform.ConfigureRuntime()
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run は完了した初期化・検査だけをJSONへ出力し、秘密や未検証のreadyを表示しない。
func run(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: oimobbs init|check|board|admission|anonymous|admin|audit|control|pack|reserve|backup|restore|evidence|logs|serve|validation-serve|healthcheck --config <path>")
	}
	action := args[0]
	if handler := commandHandler(action); handler != nil {
		return handler(args[1:], out, diagnostics)
	}
	if action != "init" && action != "check" {
		return errors.New("利用可能: init、check、board、admission、anonymous、admin、audit、control、pack、reserve、backup、restore、evidence verify-export、logs enable-required-gc、serve、validation-serve、healthcheck。")
	}
	return runBootstrap(action, args[1:], out, diagnostics)
}

// commandHandler は各管理コマンドの入口を返す。未知の名前はnilとなる。
func commandHandler(action string) func([]string, io.Writer, io.Writer) error {
	return map[string]func([]string, io.Writer, io.Writer) error{
		"restore": runRestore, "evidence": runEvidence, "backup": runBackup, "reserve": runReserve,
		"pack": runPack, "control": runControl, "logs": runLogs, "audit": runAudit,
		"serve": runServe, "validation-serve": runValidation,
		"anonymous": runAnonymous, "admission": runAdmission, "board": runBoard,
		"admin": func(args []string, out, diagnostics io.Writer) error {
			return runAdmin(args, os.Stdin, out, diagnostics)
		},
		"healthcheck": func(args []string, out, diagnostics io.Writer) error {
			return runHealthcheck(args, diagnostics)
		},
	}[action]
}

// runBootstrap は初期化または非変更検査の成功結果だけを出力する。
func runBootstrap(action string, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "起動用JSONのpath")
	var name string
	if action == "init" {
		flags.StringVar(&name, "name", "OimoBBS", "初期サイト名")
	}
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := bootstrap.LoadConfig(*config)
	if err != nil {
		return err
	}
	var report bootstrap.Report
	if action == "init" {
		report, err = bootstrap.Initialize(cfg, name)
	} else {
		report, err = bootstrap.Check(cfg)
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
