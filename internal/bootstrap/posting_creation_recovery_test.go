// 起動の事前検査を通して、初回WAL確定とcurrent設置の間の停止から復旧する。
package bootstrap

import (
	"context"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRepositoryRecoversUnreferencedCreation(t *testing.T) {
	cfg, repo, info := postingRepositoryFixture(t)
	frame := persistentFrame(t)
	result := repo.Post(context.Background(), info.ID, 0, frame, []byte(`{"fixture":true}`))
	if result.Status != store.Durable {
		t.Fatal(result)
	}
	b := repo.posting[info.ID]
	var day uint64
	for d, journal := range b.journals {
		if len(journal.Entries()) == 2 {
			day = d
		}
	}
	if day == 0 {
		t.Fatal("expected proposal and decision journal")
	}
	threadDir := filepath.Join(b.threadsDir, fmt.Sprint(result.ThreadKey))
	journalPath := filepath.Join(b.evidenceDir, fmt.Sprint(day), "control-000001.wal")
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	// 署名済みproposalだけと完全初回WALを残し、current設置前の状態を再現する。
	f, err := os.Open(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Seek(store.HeaderSize, 0); err != nil {
		t.Fatal(err)
	}
	frames, size, readErr := store.ReadWALBlock(f)
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(frames) != 1 {
		t.Fatal(readErr, closeErr)
	}
	if err = os.Truncate(journalPath, store.HeaderSize+size); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(filepath.Join(threadDir, "current.json")); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		opened, err := OpenPostingRepository(cfg, postingCaptureFixture)
		if err != nil {
			t.Fatal(err)
		}
		p := opened.posting[info.ID].threads[result.ThreadKey]
		if p == nil || p.Snapshot(domain.Time(time.Now().UnixNano())) == nil {
			opened.Close()
			t.Fatal("recovered post missing")
		}
		retry := opened.Post(context.Background(), info.ID, 0, frame, []byte(`{"fixture":true}`))
		if retry.Status != store.Durable || !retry.Duplicate || retry.ThreadKey != result.ThreadKey {
			opened.Close()
			t.Fatal(retry)
		}
		if err = opened.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
