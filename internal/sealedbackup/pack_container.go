// 一時的な暗号化コンテナを期限付きで動かし、失敗時は自分の個体だけを停止する。
package sealedbackup

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

// packContainer はCLI終了後に残り得るコンテナも、呼出元の取消とは独立して回収する。
func packContainer(ctx context.Context, o SyncOptions, source, name string, out io.Writer) error {
	suffix, e := randomSuffix()
	if e != nil {
		return e
	}
	container := "oimo-seal-helper-" + suffix
	job, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "--name", container, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint", "oimoseal", "-v", source + ":/backup:ro", o.Image, "pack", "--source", "/backup", "--name", name, "--output", "-"}
	diag := &cappedBuffer{limit: 2048}
	if e = o.Runner(job, "docker", args, nil, out, diag); e == nil {
		return nil
	}
	original := commandFailure("backup encryption", e, diag)
	cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
	defer stop()
	diag = &cappedBuffer{limit: 2048}
	if e = o.Runner(cleanup, "docker", []string{"rm", "-f", container}, nil, io.Discard, diag); e != nil {
		if !diag.overflow && strings.Contains(string(diag.body), "No such container: "+container) {
			return original
		}
		return errors.Join(original, commandFailure("backup helper cleanup", e, diag))
	}
	return original
}
