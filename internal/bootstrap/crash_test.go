// 子プロセスを保存境界で強制終了し、再実行が部分初期化を成功扱いしないことを確かめる。
package bootstrap

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"oimobbs/internal/platform"
)

func TestBootstrapCrash(t *testing.T) {
	if path := os.Getenv("OIMO_TEST_BOOTSTRAP_CONFIG"); path != "" {
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		stage := os.Getenv("OIMO_TEST_BOOTSTRAP_STOP")
		_, err = initialize(cfg, "停止点試験", func(point string) {
			if point == stage {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		})
		t.Fatalf("child did not stop: %v", err)
	}
	for _, stage := range []string{"directory", "keys", "site", "complete"} {
		t.Run(stage, func(t *testing.T) {
			cfg := testConfig(t)
			b, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(cfg.DataDir), "crash.json")
			mustWrite(t, path, b)
			cmd := exec.Command(os.Args[0], "-test.run=^TestBootstrapCrash$")
			cmd.Env = append(os.Environ(), "OIMO_TEST_BOOTSTRAP_CONFIG="+path, "OIMO_TEST_BOOTSTRAP_STOP="+stage)
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("child result %v: %s", err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("child did not receive SIGKILL: %v %s", err, output)
			}
			lock, err := platform.Lock(cfg.DataDir)
			if err != nil {
				t.Fatal("lock survived crash", err)
			}
			if err = platform.Unlock(lock); err != nil {
				t.Fatal(err)
			}
			_, err = Check(cfg)
			if stage == "complete" && err != nil {
				t.Fatal("synced instance lost", err)
			}
			if stage != "complete" && err == nil {
				t.Fatal("partial instance accepted")
			}
			if _, err = Initialize(cfg, "再初期化"); err == nil {
				t.Fatal("partial or complete instance overwritten")
			}
		})
	}
}
