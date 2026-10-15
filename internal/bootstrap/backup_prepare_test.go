// 一括作成の排他連続性、正本解放後の隔離再生、配置拒否、途中失敗の出力保持を検証する。
package bootstrap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"oimobbs/internal/platform"
)

func TestBackupPreparationPipeline(t *testing.T) {
	cfg, output := backupFixture(t)
	parent := filepath.Dir(output)
	keys := filepath.Join(parent, "keys-output")
	work := filepath.Join(parent, "work")
	if e := os.Mkdir(work, 0700); e != nil {
		t.Fatal(e)
	}
	stages := []string{}
	report, e := prepareOfflineBackup(context.Background(), cfg, output, keys, work, time.Now, func(stage string) error {
		stages = append(stages, stage)
		if stage != "source_closed" {
			if lock, e := platform.Lock(cfg.DataDir); e == nil {
				_ = platform.Unlock(lock)
				t.Fatal("source lock released between stages")
			}
			return nil
		}
		// 正本のpath自体がなくても残りの再生工程が完了する。
		return os.Rename(cfg.DataDir, cfg.DataDir+"-unavailable")
	})
	if e != nil || !report.Complete || report.Phase != "complete" || report.RestoreReady || !report.Replay.Replayed || report.Capture.ID != report.Keys.ID || report.Capture.ID != report.Replay.ID || len(stages) != 3 {
		t.Fatal(report, e, stages)
	}
	if e = os.Rename(cfg.DataDir+"-unavailable", cfg.DataDir); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(work)
	if e != nil || len(entries) != 0 {
		t.Fatal("replay work remains", entries, e)
	}
	newOutput := filepath.Join(parent, "new-copy")
	for _, paths := range [][3]string{{newOutput, keys, work}, {newOutput, newOutput, work}, {newOutput, filepath.Join(newOutput, "nested"), work}, {newOutput, filepath.Join(parent, "new-keys"), cfg.DataDir}, {cfg.DataDir, filepath.Join(parent, "new-keys"), work}} {
		r, e := PrepareOfflineBackup(context.Background(), cfg, paths[0], paths[1], paths[2])
		if e == nil || r.Phase != "preflight" || r.Complete {
			t.Fatal(paths, r, e)
		}
		if _, e = os.Stat(newOutput); !os.IsNotExist(e) {
			t.Fatal("preflight created output", e)
		}
	}
	r, e := openBackupRepository(cfg)
	if e != nil {
		t.Fatal(e)
	}
	blocked, e := PrepareOfflineBackup(context.Background(), cfg, newOutput, filepath.Join(parent, "new-keys"), work)
	if e == nil || blocked.Phase != "source_open" || blocked.Complete {
		t.Fatal(blocked, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = PrepareOfflineBackup(ctx, cfg, newOutput, filepath.Join(parent, "new-keys"), work); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	// コピー完成後の中断は鍵を生成せず、完成済みのコピーを残す。
	stop := errors.New("stop between stages")
	interrupted, e := prepareOfflineBackup(context.Background(), cfg, newOutput, filepath.Join(parent, "new-keys"), work, time.Now, func(string) error { return stop })
	if !errors.Is(e, stop) || interrupted.Complete || interrupted.Phase != "capture" || !interrupted.Capture.Verified || interrupted.Keys != nil {
		t.Fatal(interrupted, e)
	}
	if _, e = VerifyOfflineBackup(context.Background(), cfg, newOutput); e != nil {
		t.Fatal("completed copy not retained", e)
	}
	if _, e = os.Stat(filepath.Join(parent, "new-keys")); !os.IsNotExist(e) {
		t.Fatal("keys unexpectedly created", e)
	}
	// 鍵完成後に期限が到来しても、公開/完了へ進めず両出力を保持する。
	now := time.Now()
	clock := func() time.Time { return now }
	expired, e := prepareOfflineBackup(context.Background(), cfg, filepath.Join(parent, "expire-copy"), filepath.Join(parent, "expire-keys"), work, clock, func(stage string) error {
		if stage == "keys_complete" {
			now = now.Add(25 * time.Hour)
		}
		return nil
	})
	if e == nil || expired.Complete || expired.Phase != "replay" || (expired.Replay != nil && (expired.Replay.Verified || expired.Replay.Replayed)) {
		t.Fatal(expired, e)
	}
	for _, path := range []string{filepath.Join(parent, "expire-copy", "manifest.json"), filepath.Join(parent, "expire-keys", "bundle.json")} {
		if _, e = os.Stat(path); e != nil {
			t.Fatal("completed output removed", e)
		}
	}
}
