// 実製品の再起動と原本の丸ごと欠落/旧版差替えを非変更で検査する。
package bootstrap

import (
	"errors"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/evidence"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRequiredCheckpointSourceOnlyResume(t *testing.T) {
	cfg, r, info := postingRepositoryFixture(t)
	raw, at := agedRejectedFrame(t)
	key, e := r.ReserveThreadKey(t.Context(), info.ID, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	appendRejectedProposal(t, r, info.ID, key, raw, at)
	r.mu.Lock()
	e = r.enableRequiredCheckpointReaderLocked()
	r.mu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	b := r.posting[info.ID]
	day := b.requiredCheckpointDay(time.Now())
	value, e := b.worker.Submit(t.Context(), func() (any, error) { return b.journals[day].Checkpoint(time.Now()) })
	if e != nil {
		t.Fatal(e)
	}
	saved := value.(evidence.Event)
	if b.requiredCheckpointAnchored(day, saved) {
		t.Fatal("stop point already anchored")
	}
	r = reopenRejectedProduct(t, cfg, r)
	defer r.Close()
	b = r.posting[info.ID]
	if !b.requiredCheckpointAnchored(day, saved) {
		t.Fatal("source-only checkpoint not resumed")
	}
	latest, ok := b.journals[day].LatestCheckpoint()
	if !ok || latest.EventSHA != saved.EventSHA {
		t.Fatal("resume wrote another checkpoint")
	}
}

func TestRequiredCheckpointProductRestartAndGap(t *testing.T) {
	for _, mode := range []string{"missing", "rollback"} {
		t.Run(mode, func(t *testing.T) { testRequiredCheckpointProductGap(t, mode) })
	}
}

// testRequiredCheckpointProductGap はcheckpoint前の実原本と、板controlに残る後の境界を使う。
func testRequiredCheckpointProductGap(t *testing.T, mode string) {
	t.Helper()
	cfg, r, info := postingRepositoryFixture(t)
	raw, at := agedRejectedFrame(t)
	key, e := r.ReserveThreadKey(t.Context(), info.ID, time.Unix(0, int64(at)))
	if e != nil {
		t.Fatal(e)
	}
	appendRejectedProposal(t, r, info.ID, key, raw, at)
	day := time.Unix(0, int64(at)).UTC().Format("20060102")
	path := filepath.Join(cfg.DataDir, "evidence", info.ID.String(), day)
	oldFiles := requiredStartupFiles(t, path)
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e = r.reconcileRequiredRetentionLocked(t.Context())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal(e)
	}
	rowKey := "evidence_checkpoint:" + day
	if _, ok := r.posting[info.ID].control.State().Rows[rowKey]; !ok {
		t.Fatal("board checkpoint missing")
	}
	r = reopenRejectedProduct(t, cfg, r)
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.RemoveAll(path); e != nil {
		t.Fatal(e)
	}
	if mode == "rollback" {
		restoreCheckpointSource(t, path, oldFiles)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	broken, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if broken != nil {
		_ = broken.Close()
	}
	if !errors.Is(e, app.ErrEvidenceGap) {
		t.Fatal("missing journal treated as empty", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("gap refusal changed files")
	}
}

// restoreCheckpointSource は同じ実原本のcheckpoint前bytesだけを試験領域へ戻す。
func restoreCheckpointSource(t *testing.T, root string, files map[string][]byte) {
	t.Helper()
	if e := os.MkdirAll(root, 0700); e != nil {
		t.Fatal(e)
	}
	for name, data := range files {
		path := filepath.Join(root, strings.TrimPrefix(name, root+string(filepath.Separator)))
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(fmt.Sprintf("restore %s: %v", name, e))
		}
	}
}
