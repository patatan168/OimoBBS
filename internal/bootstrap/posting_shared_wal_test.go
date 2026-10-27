// 通常起動で共有本文WALを使い、明示無効化後も同じ投稿データを開けることを検査する。
package bootstrap

import (
	"bytes"
	"context"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPostingSharedWALDefaultAndDisable(t *testing.T) {
	for _, disabled := range []string{"", "1"} {
		t.Run("disabled="+disabled, func(t *testing.T) {
			t.Setenv("OIMO_DISABLE_SHARED_WAL", disabled)
			cfg := testConfig(t)
			if _, err := Initialize(cfg, "共有WAL"); err != nil {
				t.Fatal(err)
			}
			repo, err := OpenPostingRepository(cfg, postingCaptureFixture)
			if err != nil {
				t.Fatal(err)
			}
			board, err := repo.CreateBoard(context.Background(), "news", "ニュース")
			if err != nil {
				repo.Close()
				t.Fatal(err)
			}
			if (repo.posting[board.ID].sharedThreadWAL == nil) != (disabled == "1") {
				repo.Close()
				t.Fatal("起動時の共有WAL設定")
			}
			frame := persistentFrame(t)
			created := repo.Post(context.Background(), board.ID, 0, frame, []byte(`{"fixture":true}`))
			if created.Status != store.Durable {
				t.Fatal(created)
			}
			reply := persistentReply(t, frame, time.Now())
			if result := repo.Post(context.Background(), board.ID, created.ThreadKey, reply, []byte(`{"fixture":true}`)); result.Status != store.Durable {
				t.Fatal(result)
			}
			before, err := repo.Thread(context.Background(), board.ID, created.ThreadKey)
			if err != nil {
				t.Fatal(err)
			}
			groupPath := filepath.Join(repo.posting[board.ID].threadsDir, store.ThreadGroupFile)
			_, err = os.Stat(groupPath)
			if disabled == "" && err != nil || disabled == "1" && !os.IsNotExist(err) {
				t.Fatal("共有WALの保存経路", err)
			}
			if err := repo.Close(); err != nil {
				t.Fatal(err)
			}
			t.Setenv("OIMO_DISABLE_SHARED_WAL", "1")
			reopened, err := OpenPostingRepository(cfg, postingCaptureFixture)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if reopened.posting[board.ID].sharedThreadWAL != nil {
				t.Fatal("明示無効化が反映されない")
			}
			after, err := reopened.Thread(context.Background(), board.ID, created.ThreadKey)
			if err != nil || after == nil || after.PostCount != 2 || !bytes.Equal(before.DAT, after.DAT) {
				t.Fatal("無効化後の投稿本文", err)
			}
			if result := reopened.Post(context.Background(), board.ID, created.ThreadKey, reply, []byte(`{"fixture":true}`)); result.Status != store.Durable || !result.Duplicate {
				t.Fatal("無効化後の再送", result)
			}
		})
	}
}
