// 受信・送信・期限回収・定期暗号化を同じGoバイナリのCLIへ接続する。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"oimobbs/internal/sealedbackup"
)

// runBackupCommand はバックアップ操作の引数解析を各入口へ振り分ける。
func runBackupCommand(ctx context.Context, action string, args []string, in io.Reader, out io.Writer) error {
	switch action {
	case "receive":
		return runReceive(args, in, out)
	case "sweep":
		return runReceiveSweep(args, out)
	case "send":
		return runSend(ctx, args, out)
	case "sync":
		return runSync(ctx, args, out)
	case "pack":
		return runPack(ctx, args, out)
	}
	return errors.New("unknown backup command")
}

// runReceive は固定headerと標準入力を受け取り、永続化済みのACKだけを出力する。
func runReceive(args []string, in io.Reader, out io.Writer) error {
	f := flag.NewFlagSet("receive", flag.ContinueOnError)
	root := f.String("root", "", "既存0700の受信親directory")
	raw := f.String("header", "", "固定転送JSON")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *root == "" || *raw == "" {
		return errors.New("receive requires root and header")
	}
	h, e := sealedbackup.ParseHeader([]byte(*raw))
	if e != nil {
		return e
	}
	ack, e := sealedbackup.NewReceiver(*root).Receive(in, h)
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(ack)
}

// runReceiveSweep は独立timer用の期限回収結果をJSONで返す。
func runReceiveSweep(args []string, out io.Writer) error {
	f := flag.NewFlagSet("sweep", flag.ContinueOnError)
	root := f.String("root", "", "既存0700の受信親directory")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *root == "" {
		return errors.New("sweep requires root")
	}
	n, e := sealedbackup.NewReceiver(*root).Sweep()
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(map[string]int{"expired_generations_removed": n})
}

// runSend は既存の暗号文・完成記録を送信してACKを返す。
func runSend(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("send", flag.ContinueOnError)
	input := f.String("input", "", "暗号文file")
	manifest := f.String("manifest", "", "完成記録file")
	destination := f.String("destination", "", "SSH alias:/absolute/directory")
	receiver := f.String("receiver", "/usr/local/bin/oimoseal", "受信先のGoバイナリ絶対path")
	sshConfig := f.String("ssh-config", "", "任意のOpenSSH設定file")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *input == "" || *manifest == "" || *destination == "" {
		return errors.New("send requires input, manifest and destination")
	}
	ack, e := sealedbackup.Send(ctx, *input, *manifest, sealedbackup.SendOptions{Destination: *destination, Receiver: *receiver, SSHConfig: *sshConfig})
	if e != nil {
		return e
	}
	return json.NewEncoder(out).Encode(ack)
}

// runSync は定期暗号化・転送を同じGo処理へ接続する。
func runSync(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("sync", flag.ContinueOnError)
	var o sealedbackup.SyncOptions
	f.StringVar(&o.Container, "container", "", "完成ログを持つBBSコンテナ名")
	f.StringVar(&o.Image, "image", "", "同じ保存形式に対応するGoイメージ")
	f.StringVar(&o.Source, "source", "", "コピー・鍵束・暗号化公開鍵の親")
	f.StringVar(&o.Output, "output", "", "ホスト側の暗号文保存先")
	f.StringVar(&o.Destination, "destination", "", "任意のSSH alias:/absolute/directory")
	f.StringVar(&o.Receiver, "receiver", "/usr/local/bin/oimoseal", "受信先Goバイナリ絶対path")
	f.StringVar(&o.SSHConfig, "ssh-config", "", "任意のOpenSSH設定file")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("unexpected sync arguments")
	}
	return sealedbackup.Sync(ctx, o, out)
}

// runPack は検証済みのコピーを標準出力または排他的な新規ファイルへ暗号化する。
func runPack(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("pack", flag.ContinueOnError)
	source := f.String("source", "", "コピー・鍵束・ペア記録の親絶対path")
	name := f.String("name", "", "完成バックアップ名")
	output := f.String("output", "-", "新規暗号文fileまたは標準出力")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 || *source == "" || *name == "" {
		return errors.New("pack requires source and name")
	}
	write := func(w io.Writer) error { return sealedbackup.Pack(ctx, *source, *name, w, nil) }
	if *output == "-" {
		return write(out)
	}
	return newFile(*output, write)
}
