// 暗号化処理を取消した場合の補助コンテナ回収と、その失敗の通知を検査する。
package sealedbackup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestPackContainerCancellationCleanup(t *testing.T) {
	for _, state := range []string{"removed", "already-removed", "cleanup-failed"} {
		t.Run(state, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var container string
			calls := 0
			cleanupFailure := errors.New("docker unavailable during cleanup")
			runner := func(job context.Context, command string, args []string, _ io.Reader, _ io.Writer, diag io.Writer) error {
				calls++
				if command != "docker" {
					t.Fatal(command)
				}
				if args[0] == "run" {
					container = args[slices.Index(args, "--name")+1]
					cancel()
					return job.Err()
				}
				if job.Err() != nil || !slices.Equal(args, []string{"rm", "-f", container}) || !strings.HasPrefix(container, "oimo-seal-helper-") {
					t.Fatal("wrong cleanup", args, job.Err())
				}
				switch state {
				case "already-removed":
					fmt.Fprintln(diag, "Error response from daemon: No such container: "+container)
					return errors.New("exit 1")
				case "cleanup-failed":
					return cleanupFailure
				}
				return nil
			}
			e := packContainer(ctx, SyncOptions{Image: "fixture", Runner: runner}, "/fixture", "backup", io.Discard)
			if !errors.Is(e, context.Canceled) || calls != 2 {
				t.Fatal("original cancellation lost", e, calls)
			}
			if errors.Is(e, cleanupFailure) != (state == "cleanup-failed") {
				t.Fatal("cleanup failure lost", e)
			}
		})
	}
}
