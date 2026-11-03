// まとめた監査保存の耐久境界、中断後の再利用、索引への公開順序を検証する。
package bootstrap

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/postcapture"
	"oimobbs/internal/store"
)

// TestAuditBatchInterruptedBeforeIndex は保存後の中断から、欠落・重複なく同じ一覧を復元する。
func TestAuditBatchInterruptedBeforeIndex(t *testing.T) {
	cfg, repo := adminFixture(t)
	defer func() { repo.Close() }()
	repo.mu.Lock()
	for i := 0; i < 130; i++ {
		if err := appendControl(repo.site, "site_name_update", []store.Mutation{mutation("site", "state", repo.site.State().Rows["site:state"].Value, nil)}, []string{}); err != nil {
			repo.mu.Unlock()
			t.Fatal(err)
		}
	}
	repo.mu.Unlock()
	query := auditQuery{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Second), Limit: 200}
	repo.checkpoint = func(stage string) {
		if stage == "audit:durable" {
			panic("after batch sync, before index publication")
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("durable checkpoint not reached")
			}
		}()
		_, _ = collectAuditFixture(repo, t.Context(), query)
	}()
	if repo.auditIndex.count != 0 {
		t.Fatal("batch published before durable checkpoint completed", repo.auditIndex.count)
	}
	path := filepath.Join(cfg.DataDir, "audit", siteID(repo.site.State()).String(), time.Now().UTC().Format("20060102"), "control-000001.wal")
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Seek(64, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	largest := 0
	for {
		frames, _, err := store.ReadWALBlock(file)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		largest = max(largest, len(frames))
	}
	file.Close()
	if largest < 2 || largest > store.MaxCommitFrames {
		t.Fatal("audit entries were not committed in bounded groups", largest)
	}
	repo.checkpoint = func(string) {}
	want, err := collectAuditFixture(repo, t.Context(), query)
	if err != nil || len(want) != 131 {
		t.Fatal("resume lost or duplicated entries", len(want), err)
	}
	if err := repo.Close(); err != nil {
		t.Fatal(err)
	}
	repo, err = OpenPostingRepository(cfg, postcapture.Validate)
	if err != nil {
		t.Fatal(err)
	}
	got, err := collectAuditFixture(repo, t.Context(), query)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("restart changed committed audit entries", len(got), err)
	}
}
