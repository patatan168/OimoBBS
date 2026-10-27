// Command oimoupdate は掲示板と独立して動き、確認済みコミットの検証・更新をホストで行う。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"oimobbs/internal/selfupdate"
)

func main() {
	path := flag.String("config", "", "所有者専用の更新器JSON設定")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: oimoupdate --config /etc/oimobbs/update-agent.json")
		os.Exit(2)
	}
	c, err := selfupdate.LoadConfig(*path)
	if err == nil {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		err = selfupdate.Serve(ctx, c)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
