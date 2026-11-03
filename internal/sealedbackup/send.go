// OpenSSHのalias・鍵管理・ホスト鍵検証を使い、Goの受信器による設置ACKまで確認する。
package sealedbackup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"strings"
	"time"
)

// SendOptions は接続先と配布済みの受信バイナリ。Runnerは通常省略する。
type SendOptions struct {
	Destination, Receiver, SSHConfig string
	Timeout                          time.Duration
	Runner                           CommandRunner
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

// SSHArguments は受信先へ実行するGoバイナリだけを引用し、スクリプトを送らない。
func SSHArguments(destination, receiver string, h Header) ([]string, error) {
	alias, root, e := ParseDestination(destination)
	if e != nil {
		return nil, e
	}
	if !filepath.IsAbs(receiver) || filepath.Clean(receiver) != receiver || strings.ContainsAny(receiver, "\x00\r\n") {
		return nil, errors.New("receiver requires canonical absolute binary path")
	}
	raw, e := json.Marshal(h)
	if e != nil {
		return nil, e
	}
	command := shellQuote(receiver) + " receive --root " + shellQuote(root) + " --header " + shellQuote(string(raw))
	return []string{"-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oConnectTimeout=10", "--", alias, command}, nil
}

// Send は暗号文をfile descriptorでOpenSSHへ渡し、正しいACKがある場合だけ成功する。
func Send(ctx context.Context, target, manifestPath string, options SendOptions) (ack Acknowledgement, err error) {
	m, e := LoadManifest(manifestPath)
	if e != nil {
		return ack, e
	}
	f, e := openPrivate(target)
	if e != nil {
		return ack, e
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	info, e := f.Stat()
	if e != nil {
		return ack, e
	}
	h := Header{1, m, info.Size()}
	if e = NewReceiver("").valid(h); e != nil {
		return ack, e
	}
	if options.Receiver == "" {
		options.Receiver = "/usr/local/bin/oimoseal"
	}
	args, e := SSHArguments(options.Destination, options.Receiver, h)
	if e != nil {
		return ack, e
	}
	if options.SSHConfig != "" {
		args = append([]string{"-F", options.SSHConfig}, args...)
	}
	if options.Timeout <= 0 {
		options.Timeout = 180 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, options.Timeout)
	defer cancel()
	runner := options.Runner
	if runner == nil {
		runner = runCommand
	}
	out, diag := &cappedBuffer{limit: metadataLimit}, &cappedBuffer{limit: 2048}
	if e = runner(ctx, "ssh", args, f, out, diag); e != nil {
		return ack, commandFailure("sealed backup transfer; installation acknowledgement unknown", e, diag)
	}
	if out.overflow {
		return ack, errors.New("oversized backup acknowledgement")
	}
	if e = strictjson.DecodeLimit(out.body, &ack, metadataLimit); e != nil {
		return ack, fmt.Errorf("invalid backup acknowledgement: %w", e)
	}
	if ack != acknowledgement(m, "installed") && ack != acknowledgement(m, "existing") {
		return ack, errors.New("invalid backup acknowledgement")
	}
	return ack, nil
}
