// 板作成・予約のSync境界でSIGKILLし、同じ永続intentから一度だけ再開する。
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestBoardProvisionCrash(t *testing.T) {
	if path := os.Getenv("OIMO_TEST_BOARD_CONFIG"); path != "" {
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatal(err)
		}
		stage := os.Getenv("OIMO_TEST_BOARD_STOP")
		repo, err := openRepository(cfg, func(point string) {
			if point == stage {
				_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		var b BoardInfo
		if owner := os.Getenv("OIMO_TEST_BOARD_ADMIN"); owner != "" {
			var id domain.ID
			if err = json.Unmarshal([]byte(strconv.Quote(owner)), &id); err != nil {
				t.Fatal(err)
			}
			repo.mu.Lock()
			b, err = repo.createBoardWithPolicyLocked(context.Background(), "persistent", "停止点の板", &id, os.Getenv("OIMO_TEST_BOARD_POLICY"))
			repo.mu.Unlock()
		} else {
			b, err = repo.CreateBoard(context.Background(), "persistent", "停止点の板")
		}
		if err != nil {
			t.Fatal(err)
		}
		if stage == "reservation" {
			_, err = repo.ReserveThreadKey(context.Background(), b.ID, time.Unix(100, 0))
		}
		t.Fatalf("child failed to stop: %v", err)
	}
	for _, stage := range []string{"job", "provisioning", "board_directory", "board", "active", "completed", "reservation"} {
		t.Run(stage, func(t *testing.T) {
			cfg := testConfig(t)
			if _, err := Initialize(cfg, "停止点試験"); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(cfg.DataDir), "board-crash.json")
			mustWrite(t, path, raw)
			cmd := exec.Command(os.Args[0], "-test.run=^TestBoardProvisionCrash$")
			cmd.Env = append(os.Environ(), "OIMO_TEST_BOARD_CONFIG="+path, "OIMO_TEST_BOARD_STOP="+stage)
			output, err := cmd.CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("child %v: %s", err, output)
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatalf("child not killed: %v %s", err, output)
			}
			ids, err := childIDs(filepath.Join(cfg.DataDir, "jobs"))
			if err != nil || len(ids) != 1 {
				t.Fatal(ids, err)
			}
			job, err := inspectJob(cfg.DataDir, ids[0])
			if err != nil {
				t.Fatal(err)
			}
			if stage != "completed" && stage != "reservation" {
				if _, err = Check(cfg); err == nil {
					t.Fatal("unfinished job passed check")
				}
			}
			repo, err := OpenRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			boards, err := repo.Boards()
			if err != nil || len(boards) != 1 || boards[0].ID != job.Parameters.BoardID || boards[0].Key != "persistent" {
				t.Fatal(boards, err)
			}
			again, err := repo.CreateBoard(context.Background(), "persistent", "停止点の板")
			if err != nil || again.ID != job.Parameters.BoardID {
				t.Fatal("duplicate provisioning", err)
			}
			if stage == "reservation" {
				n, err := repo.ReserveThreadKey(context.Background(), again.ID, time.Unix(50, 0))
				if err != nil || n != 101 {
					t.Fatal("reservation lost", n, err)
				}
			}
			if err = repo.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err = Check(cfg); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestIncompleteBoardControlRecovery(t *testing.T) {
	for _, cut := range []int{0, 1, 63, 64, 80, -1} {
		t.Run(fmt.Sprint(cut), func(t *testing.T) {
			cfg := testConfig(t)
			if _, err := Initialize(cfg, "試験"); err != nil {
				t.Fatal(err)
			}
			repo, err := OpenRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			job, err := repo.newJob("pending", "作成途中")
			if err != nil {
				t.Fatal(err)
			}
			frame, err := controlFrame(store.ControlState{}, job.ID, job.Created, "provision_board", []store.Mutation{mutation("job", job.ID.String(), job, nil)}, []string{job.Parameters.BoardID.String()})
			if err != nil {
				t.Fatal(err)
			}
			log, err := store.CreateControl(filepath.Join(cfg.DataDir, "jobs", job.ID.String()), store.Header{Kind: 6, Owner: job.ID, Generation: 1}, frame, validateProvisionJob)
			if err != nil {
				t.Fatal(err)
			}
			if err = log.Close(); err != nil {
				t.Fatal(err)
			}
			d := boardDirectory{Key: job.Parameters.Key, Aliases: []string{}, Status: "provisioning", JobID: job.ID}
			if err = appendControl(repo.site, "board_provisioning", []store.Mutation{mutation("board_directory", job.Parameters.BoardID.String(), d, nil)}, []string{job.Parameters.BoardID.String()}); err != nil {
				t.Fatal(err)
			}
			if err = repo.Close(); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(cfg.DataDir, "boards", job.Parameters.BoardID.String())
			if err = makePrivateDir(dir); err != nil {
				t.Fatal(err)
			}
			if err = makePrivateDir(filepath.Join(dir, "control")); err != nil {
				t.Fatal(err)
			}
			frame, err = boardInitialFrame(job)
			if err != nil {
				t.Fatal(err)
			}
			header, _ := store.EncodeHeader(store.Header{Kind: 2, Owner: job.Parameters.BoardID, Generation: 1})
			block, e := store.EncodeWALBlock([][]byte{frame})
			if e != nil {
				t.Fatal(e)
			}
			raw := append(header, block...)
			n := cut
			if n < 0 {
				n = len(raw)
			}
			mustWrite(t, filepath.Join(dir, "control", "control-000001.wal"), raw[:n])
			repo, err = OpenRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.Close(); err != nil {
				t.Fatal(err)
			}
			rows, err := ListBoards(cfg)
			if err != nil || len(rows) != 1 || rows[0].ID != job.Parameters.BoardID {
				t.Fatal(rows, err)
			}
		})
	}
}
