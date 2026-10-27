// 公式Gitの固定ブランチを取得し、確認済みコミットを隔離してホスト設定のコマンドに渡す。
package selfupdate

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type gitWorker struct {
	config Config
	remote string
}

func (w gitWorker) git(ctx context.Context, args ...string) ([]byte, error) {
	args = append([]string{"-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never", "--git-dir=" + filepath.Join(w.config.StateDir, "repository.git")}, args...)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return raw, fmt.Errorf("git: %w: %s", err, raw)
	}
	return raw, nil
}

func (w gitWorker) latest(ctx context.Context, current string) (string, error) {
	cache := filepath.Join(w.config.StateDir, "repository.git")
	if _, err := os.Stat(cache); errors.Is(err, os.ErrNotExist) {
		if raw, err := exec.CommandContext(ctx, "git", "-c", "core.hooksPath=/dev/null", "init", "--bare", cache).CombinedOutput(); err != nil {
			return "", fmt.Errorf("git init: %w: %s", err, raw)
		}
	}
	remote := w.remote
	if remote == "" {
		remote = RepositoryURL
	}
	if _, err := w.git(ctx, "fetch", "--no-tags", "--no-recurse-submodules", "--", remote, "refs/heads/main:refs/heads/update-main"); err != nil {
		return "", err
	}
	raw, err := w.git(ctx, "rev-parse", "refs/heads/update-main^{commit}")
	latest := strings.TrimSpace(string(raw))
	if err != nil || !revisionPattern.MatchString(latest) {
		return "", errors.New("invalid upstream revision")
	}
	if _, err := w.git(ctx, "merge-base", "--is-ancestor", current, latest); err != nil {
		return "", errors.New("installed revision is not an ancestor of main")
	}
	return latest, nil
}

func (w gitWorker) prepare(ctx context.Context, s State) error {
	job := filepath.Join(w.config.StateDir, "jobs", s.Job)
	if err := os.MkdirAll(filepath.Dir(job), 0700); err != nil {
		return err
	}
	if err := os.Mkdir(job, 0700); err != nil {
		return err
	}
	request, err := json.Marshal(map[string]string{"job": s.Job, "current_revision": s.CurrentRevision, "revision": s.LatestRevision})
	if err != nil {
		return err
	}
	if err := saveFile(filepath.Join(job, "request.json"), request); err != nil {
		return err
	}
	source := filepath.Join(job, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		return err
	}
	// archiveへ可変のブランチ名は渡さず、確認済みの完全SHAだけを使う。
	archive := exec.CommandContext(ctx, "git", "--git-dir="+filepath.Join(w.config.StateDir, "repository.git"), "archive", "--format=tar", s.LatestRevision)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		return err
	}
	if err := archive.Start(); err != nil {
		return err
	}
	err = extractSource(pipe, source)
	if err != nil {
		_ = archive.Process.Kill()
	}
	waitErr := archive.Wait()
	if err != nil {
		return err
	}
	if waitErr != nil {
		return waitErr
	}
	return w.command(ctx, w.config.PrepareCommand, s)
}

func (w gitWorker) apply(ctx context.Context, s State) error {
	return w.command(ctx, w.config.ApplyCommand, s)
}

// command はシェルを介さず固定引数を展開し、子プロセスも含めて期限内に終了させる。
func (w gitWorker) command(ctx context.Context, configured []string, s State) error {
	job := filepath.Join(w.config.StateDir, "jobs", s.Job)
	r := strings.NewReplacer("{source}", filepath.Join(job, "source"), "{revision}", s.LatestRevision, "{job}", job)
	args := make([]string, len(configured))
	for i, value := range configured {
		args[i] = r.Replace(value)
	}
	log, err := os.OpenFile(filepath.Join(job, "update.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Dir, cmd.Stdout, cmd.Stderr = job, log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 5 * time.Second
	return cmd.Run()
}

// extractSource はGit管理下の通常ファイルだけを展開し、リンク・絶対パス・容量超過を拒否する。
func extractSource(input io.Reader, directory string) error {
	reader := tar.NewReader(input)
	var size int64
	for count := 0; count < 100000; count++ {
		h, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		// git archiveはコミット情報をPAXの共通ヘッダーとして先頭に置く。
		if h.Typeflag == tar.TypeXGlobalHeader && h.Size <= 8192 {
			continue
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !filepath.IsLocal(name) || strings.Contains(name, "\\") {
			return errors.New("unsafe archive path")
		}
		path := filepath.Join(directory, name)
		if h.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(path, 0700); err != nil {
				return err
			}
			continue
		}
		size += h.Size
		if h.Typeflag != tar.TypeReg || h.Size < 0 || size > 1<<30 {
			return errors.New("unsupported or oversized source archive")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(h.Mode)&0700)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyN(f, reader, h.Size)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return errors.New("source archive has too many entries")
}
