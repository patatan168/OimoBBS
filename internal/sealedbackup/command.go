// 外部の接続・Docker操作だけを既存CLIへ委ね、出力量と待機時間を制限する。
package sealedbackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"
)

// CommandRunner は子プロセスの引数とストリームを結合する。nilなら実OSコマンドを使う。
type CommandRunner func(context.Context, string, []string, io.Reader, io.Writer, io.Writer) error

// runCommand は取消と標準入出力の回収期限を子プロセスにも適用する。
func runCommand(ctx context.Context, name string, args []string, in io.Reader, out, diagnostics io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = diagnostics
	cmd.WaitDelay = 5 * time.Second
	return errors.Join(cmd.Run(), ctx.Err())
}

type cappedBuffer struct {
	body     []byte
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	keep := min(len(p), b.limit-len(b.body))
	b.body = append(b.body, p[:keep]...)
	b.overflow = b.overflow || keep < n
	return n, nil
}
func commandFailure(name string, e error, diagnostics *cappedBuffer) error {
	return fmt.Errorf("%s failed: %w: %s", name, e, diagnostics.body)
}
