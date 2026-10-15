// 復旧用ディスク予約の停止中操作をCLIへ接続する。
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
)

func runReserve(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: reserve status|prepare|release --config <path> [--apply] [--remaining-mib 0..255]")
	}
	action := args[0]
	if action != "status" && action != "prepare" && action != "release" {
		return errors.New("unknown reserve action")
	}
	flags := flag.NewFlagSet("reserve "+action, flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "起動用JSONのpath")
	apply := false
	remaining := -1
	if action != "status" {
		flags.BoolVar(&apply, "apply", false, "停止中の保存先へ適用")
	}
	if action == "release" {
		flags.IntVar(&remaining, "remaining-mib", -1, "解放後に残すMiB（0..255、必須）")
	}
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if action == "release" && (remaining < 0 || remaining > 255) {
		return errors.New("remaining-mib must be specified in 0..255")
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	report, e := bootstrap.ManageEmergencyReserve(cfg, action, int64(remaining)<<20, apply)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(report)
}
