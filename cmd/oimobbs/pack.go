// 排他を確保した停止中サイトの投稿pack検証・適用CLI。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/bootstrap"
	"oimobbs/internal/domain"
	"oimobbs/internal/postcapture"
)

func runPack(args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 || (args[0] != "enable" && args[0] != "compact" && args[0] != "reclaim" && args[0] != "maintain") {
		return errors.New("usage: pack enable --config <path>, or pack compact/reclaim --config <path> --board <board ID> --thread <key> [--level 0|1|6|9] [--apply], or pack maintain --config <path> [--limit 100] [--after <next>] [--apply]")
	}
	flags := flag.NewFlagSet("pack "+args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	config := flags.String("config", "config.json", "停止中のサイト設定JSON")
	var owner string
	var key uint64
	level := 6
	apply := false
	limit := 100
	after := ""
	if args[0] == "maintain" {
		flags.IntVar(&limit, "limit", 100, "一回に調べるスレッド上限（1..1000）")
		flags.StringVar(&after, "after", "", "前回結果のnext cursor")
		flags.BoolVar(&apply, "apply", false, "必要な圧縮と旧世代回収を適用")
	}
	if args[0] != "enable" && args[0] != "maintain" {
		flags.StringVar(&owner, "board", "", "板UUID")
		flags.Uint64Var(&key, "thread", 0, "スレッドキー")
		if args[0] == "compact" {
			flags.IntVar(&level, "level", 6, "0=raw、保存Zstandardの生成方針=1/6/9")
		}
		flags.BoolVar(&apply, "apply", false, "照合後に切替または旧世代回収を適用（既定は検証のみ）")
	}
	if e := flags.Parse(args[1:]); e != nil {
		return e
	}
	if flags.NArg() != 0 {
		return errors.New("positional arguments are not allowed")
	}
	var id domain.ID
	if args[0] != "enable" && args[0] != "maintain" {
		raw, _ := json.Marshal(owner)
		if e := json.Unmarshal(raw, &id); e != nil {
			return e
		}
		if key == 0 || (level != 0 && level != 1 && level != 6 && level != 9) {
			return errors.New("valid thread key and level required")
		}
	}
	cfg, e := bootstrap.LoadConfig(*config)
	if e != nil {
		return e
	}
	r, e := bootstrap.OpenPostingRepository(cfg, postcapture.Validate)
	if e != nil {
		return e
	}
	var result any
	if args[0] == "enable" {
		result, e = r.EnablePostingPacks(context.Background())
	} else if args[0] == "maintain" {
		result, e = r.MaintainPostingPacks(context.Background(), limit, after, apply)
	} else if args[0] == "reclaim" {
		result, e = r.ReclaimThreadPack(context.Background(), id, key, apply)
	} else {
		result, e = r.CompactThread(context.Background(), id, key, level, apply)
	}
	e = errors.Join(e, r.Close())
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(result)
}
