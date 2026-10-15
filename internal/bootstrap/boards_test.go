// 永続板の作成、再送、復旧、管理操作の排他を実ファイルで検証する。
package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentBoard(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "板試験"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first, err := repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil {
		t.Fatal(err)
	}
	same, err := repo.CreateBoard(context.Background(), "news", "ニュース")
	if err != nil || same.ID != first.ID {
		t.Fatal("board retry", err)
	}
	if _, err = repo.CreateBoard(context.Background(), "news", "別の名前"); err == nil {
		t.Fatal("changed retry accepted")
	}
	for _, key := range []string{"test", "web", "admin", "Bad", "../x"} {
		if _, err = repo.CreateBoard(context.Background(), key, "不正"); err == nil {
			t.Fatal(key)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = repo.CreateBoard(ctx, "cancelled", "取消"); err == nil {
		t.Fatal("cancelled create")
	}
	n, err := repo.ReserveThreadKey(context.Background(), first.ID, time.Unix(100, 0))
	if err != nil || n != 100 {
		t.Fatal(n, err)
	}
	if _, err = Check(cfg); err == nil {
		t.Fatal("second owner accepted")
	}
	if err = repo.Close(); err != nil {
		t.Fatal(err)
	}
	checked, err := Check(cfg)
	if err != nil || checked.BoardCount != 1 {
		t.Fatal(checked, err)
	}
	repo, err = OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	boards, err := repo.Boards()
	if err != nil || len(boards) != 1 || boards[0].ID != first.ID || boards[0].Name != "ニュース" {
		t.Fatal(boards, err)
	}
	n, err = repo.ReserveThreadKey(context.Background(), first.ID, time.Unix(50, 0))
	if err != nil || n != 101 {
		t.Fatal("key reused after clock regression", n, err)
	}
}
func TestPersistentBoardDamage(t *testing.T) {
	for _, tc := range []string{"missing_control", "crc", "orphan", "thread_data", "symlink"} {
		t.Run(tc, func(t *testing.T) {
			cfg := testConfig(t)
			if _, err := Initialize(cfg, "試験"); err != nil {
				t.Fatal(err)
			}
			repo, err := OpenRepository(cfg)
			if err != nil {
				t.Fatal(err)
			}
			b, err := repo.CreateBoard(context.Background(), "news", "ニュース")
			if err != nil {
				t.Fatal(err)
			}
			if err = repo.Close(); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(cfg.DataDir, "boards", b.ID.String())
			switch tc {
			case "missing_control":
				if err = os.Remove(filepath.Join(dir, "control", "control.current")); err != nil {
					t.Fatal(err)
				}
			case "crc":
				p := filepath.Join(dir, "control", "control-000001.wal")
				raw, _ := os.ReadFile(p)
				raw[len(raw)-12] ^= 1
				mustWrite(t, p, raw)
			case "orphan":
				if err = os.Mkdir(filepath.Join(cfg.DataDir, "boards", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0700); err != nil {
					t.Fatal(err)
				}
			case "thread_data":
				mustWrite(t, filepath.Join(dir, "threads", "unverified"), []byte("unknown"))
			case "symlink":
				p := filepath.Join(dir, "threads")
				if err = os.Remove(p); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(t.TempDir(), p); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = Check(cfg); err == nil {
				t.Fatal("damage accepted by check")
			}
			if opened, err := OpenRepository(cfg); err == nil {
				opened.Close()
				t.Fatal("damaged repository opened")
			}
		})
	}
}

func TestBoardConcurrentReservations(t *testing.T) {
	cfg := testConfig(t)
	if _, err := Initialize(cfg, "並行試験"); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenRepository(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	results := make(chan uint64, 16)
	errors := make(chan error, 16)
	for range 16 {
		go func() {
			b, err := repo.CreateBoard(context.Background(), "same", "同じ板")
			if err != nil {
				errors <- err
				return
			}
			n, err := repo.ReserveThreadKey(context.Background(), b.ID, time.Unix(1, 0))
			if err != nil {
				errors <- err
				return
			}
			results <- n
		}()
	}
	seen := map[uint64]bool{}
	for range 16 {
		select {
		case err := <-errors:
			t.Fatal(err)
		case n := <-results:
			if n < 1 || n > 16 || seen[n] {
				t.Fatal("duplicate reservation", n)
			}
			seen[n] = true
		}
	}
	rows, err := repo.Boards()
	if err != nil || len(rows) != 1 {
		t.Fatal(rows, err)
	}
}
