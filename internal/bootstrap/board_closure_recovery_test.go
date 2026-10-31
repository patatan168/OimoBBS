// 閉鎖記録の保存前後でプロセスを強制終了し、閉鎖状態と保持中の本文を復旧する。
package bootstrap

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"oimobbs/internal/postcapture"
)

func TestBoardClosureCrash(t *testing.T) {
	if config := os.Getenv("OIMO_TEST_CLOSURE_CONFIG"); config != "" {
		cfg, err := LoadConfig(config)
		if err != nil {
			t.Fatal(err)
		}
		repo, err := openPostingRepository(cfg, func(point string) {
			if point == os.Getenv("OIMO_TEST_CLOSURE_STOP") {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		}, postcapture.Validate)
		if err != nil {
			t.Fatal(err)
		}
		boards, err := repo.Boards()
		if err != nil || len(boards) != 1 {
			t.Fatal(boards, err)
		}
		c := newAdminClient(t, repo)
		if c.login(adminTestSecret) != 303 || c.reauth(adminTestSecret) != 200 {
			t.Fatal("auth")
		}
		path, fields := closureForm(t, c, boards[0].ID)
		fields.Set("confirm_key", boards[0].Key)
		c.request("POST", path, fields.Encode(), http.Header{"Content-Type": {"application/x-www-form-urlencoded"}})
		t.Fatal("child did not stop")
	}
	for _, point := range []string{"board_close_prepared", "board_close_durable", "board_close_saved"} {
		t.Run(point, func(t *testing.T) {
			cfg, repo := adminFixture(t)
			board, err := repo.CreateBoard(t.Context(), "crashclose", "閉鎖復旧")
			if err != nil {
				t.Fatal(err)
			}
			form := formServer(t, repo, siteID(repo.site.State()), board.ID)
			post, err := sendForm(form, url.Values{"bbs": {"crashclose"}, "subject": {"復旧後も保持するログ"}, "MESSAGE": {"閉鎖では消さない本文"}, "oimo_request_id": {"closure-crash-post"}})
			form.Close()
			if err != nil || !post.Accepted {
				t.Fatal(post, err)
			}
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(cfg)
			config := filepath.Join(filepath.Dir(cfg.DataDir), "closure-crash.json")
			mustWrite(t, config, raw)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestBoardClosureCrash$")
			cmd.Env = append(os.Environ(), "OIMO_TEST_CLOSURE_CONFIG="+config, "OIMO_TEST_CLOSURE_STOP="+point)
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("child %v: %s", err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("not SIGKILL: %v %s", err, output)
			}
			repo, err = OpenPostingRepository(cfg, postcapture.Validate)
			if err != nil {
				t.Fatal("reopen", err)
			}
			defer repo.Close()
			closed := point != "board_close_prepared"
			if got := repo.posting[board.ID].closedAt.Load() != 0; got != closed {
				t.Fatal("wrong recovered closure", got, closed)
			}
			if p := repo.posting[board.ID].threads[post.Key]; p == nil || p.Reclaimed() {
				t.Fatal("retained body was removed")
			}
			_, public, err := repo.webBoards()
			if err != nil || (len(public) == 0) != closed {
				t.Fatal(public, err)
			}
		})
	}
}
