// 未確定候補の実file配置から、非変更検査と起動時再開/不一致拒否を検査する。
package bootstrap

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

func pendingCarryFixture(t *testing.T, stage string) (Config, *Repository, domain.ID, uint64, string) {
	t.Helper()
	cfg, r, owner, key, path := erasedCarryFixture(t)
	if _, e := r.enableStorageReader(t.Context(), bodyCarrySnapshotReader, "pending_carry_test"); e != nil {
		t.Fatal(e)
	}
	m, e := store.InspectControlManifest(path)
	if e != nil {
		t.Fatal(e)
	}
	plan, e := prepareCarrySnapshotPlan(path, m, r.posting[owner].deletions[key].State())
	if e != nil {
		t.Fatal(e)
	}
	writePendingCarryFiles(t, path, plan, stage)
	return cfg, r, owner, key, path
}

// writePendingCarryFiles は各停止点で残る完成/途中prefixを再現する。
func writePendingCarryFiles(t *testing.T, path string, p carrySnapshotPlan, stage string) {
	t.Helper()
	files := map[string][]byte{"control-000002.snap": p.snapshot}
	switch stage {
	case "empty_snapshot":
		files["control-000002.snap"] = nil
	case "partial_snapshot":
		files["control-000002.snap"] = p.snapshot[:len(p.snapshot)/2]
	case "snapshot_synced":
	case "partial_delta":
		files["control-000002.wal"] = p.delta[:12]
	default:
		files["control-000002.wal"] = p.delta
	}
	switch stage {
	case "partial_current":
		files[".install-fixture"] = p.current[:len(p.current)/2]
	case "current_synced":
		files[".install-fixture"] = p.current
	case "renamed_current_with_temp":
		files["control.current"] = p.current
		files[".install-fixture"] = p.current
	}
	for name, raw := range files {
		if e := os.WriteFile(filepath.Join(path, name), raw, 0600); e != nil {
			t.Fatal(e)
		}
	}
}

func TestBodyCarryPendingSnapshotStageRestart(t *testing.T) {
	for _, stage := range []string{"empty_snapshot", "partial_snapshot", "snapshot_synced", "partial_delta", "generation_synced", "partial_current", "current_synced", "renamed_current_with_temp"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, owner, key, path := pendingCarryFixture(t, stage)
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if _, e := checkLockedPosting(cfg, false, true); e != nil {
				t.Fatal("pending prefix check", e)
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("read-only check changed pending files")
			}
			reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal("stage restart", e)
			}
			defer reopened.Close()
			assertCarryRateCount(t, reopened.posting[owner], key, 0)
			if e = reopened.CompactExpiredBodyCarry(t.Context(), owner, key); e != nil {
				t.Fatal("finish old WAL cleanup", e)
			}
			assertCarrySourceSnapshot(t, path, owner, key)
			if _, e = os.Lstat(filepath.Join(path, ".install-fixture")); !os.IsNotExist(e) {
				t.Fatal("verified temporary current remains", e)
			}
		})
	}
}

func TestBodyCarryPendingSnapshotDifferentPrefixRefused(t *testing.T) {
	for _, name := range []string{"control-000002.snap", "control-000002.wal", ".install-fixture"} {
		t.Run(name, func(t *testing.T) {
			cfg, r, _, _, path := pendingCarryFixture(t, "current_synced")
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(path, name), []byte("different prefix"), 0600); e != nil {
				t.Fatal(e)
			}
			assertCarryUnsafeStartup(t, cfg, "different_snapshot_prefix")
		})
	}
}

func TestBodyCarryPendingSnapshotChangedHistoryRefusedBeforeRepair(t *testing.T) {
	cfg, r, _, _, path := pendingCarryFixture(t, "current_synced")
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	changeOldRateCarryCRC(t, filepath.Join(path, "control-000001.wal"))
	assertCarryUnsafeStartup(t, cfg, "changed_pending_history")
}
