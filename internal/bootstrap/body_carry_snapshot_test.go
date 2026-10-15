// 実snapshot切替/旧WAL回収と停止再開、未知fileの非変更拒否を検査する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func erasedCarryFixture(t *testing.T) (Config, *Repository, domain.ID, uint64, string) {
	t.Helper()
	cfg, r, owner, key, _, _ := requiredReclaimRepositoryFixture(t, true)
	if _, e := r.ReclaimExpiredBodyCarry(t.Context(), owner, key, 128); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cfg.DataDir, "expiry", owner.String(), fmt.Sprint(key))
	return cfg, r, owner, key, path
}

func TestBodyCarrySnapshotAndPhysicalWALReclaim(t *testing.T) {
	cfg, r, owner, key, path := erasedCarryFixture(t)
	if e := r.CompactExpiredBodyCarry(t.Context(), owner, key); e != nil {
		t.Fatal(e)
	}
	assertCarrySourceSnapshot(t, path, owner, key)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := checkLockedPosting(cfg, false, true); e != nil {
		t.Fatal("snapshot check", e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal("snapshot reopen", e)
	}
	defer reopened.Close()
	assertCarryRateCount(t, reopened.posting[owner], key, 0)
	if e = reopened.CompactExpiredBodyCarry(t.Context(), owner, key); e != nil {
		t.Fatal("repeat physical reclaim", e)
	}
	assertCarrySourceSnapshot(t, path, owner, key)
}

func assertCarrySourceSnapshot(t *testing.T, path string, owner domain.ID, key uint64) {
	t.Helper()
	if _, e := os.Lstat(filepath.Join(path, "control-000001.wal")); !os.IsNotExist(e) {
		t.Fatal("old private WAL remains", e)
	}
	m, e := store.InspectControlManifest(path)
	if e != nil || m.Generation != 2 || m.Snapshot == nil {
		t.Fatal("missing snapshot", e)
	}
	state, e := inspectDeletionControl(path, owner, key)
	if e != nil || carryRowsInState(state) != 0 {
		t.Fatal("carry returned in snapshot", e)
	}
}

func TestBodyCarrySnapshotStopsResumePhysicalReclaim(t *testing.T) {
	for _, stage := range []string{"carry_snapshot:switched", "carry_snapshot:old_unlinked"} {
		t.Run(stage, func(t *testing.T) {
			cfg, r, owner, key, path := erasedCarryFixture(t)
			stop := errors.New("snapshot reclaim interrupted")
			r.posting[owner].deletionCheckpoint = func(s string) error {
				if s == stage {
					return stop
				}
				return nil
			}
			if e := r.CompactExpiredBodyCarry(t.Context(), owner, key); !errors.Is(e, stop) {
				t.Fatal("stop not reached", e)
			}
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal("stopped snapshot reopen", e)
			}
			defer reopened.Close()
			if e = reopened.CompactExpiredBodyCarry(t.Context(), owner, key); e != nil {
				t.Fatal("reclaim resume", e)
			}
			assertCarrySourceSnapshot(t, path, owner, key)
		})
	}
}

func TestBodyCarrySnapshotUnknownFileRefused(t *testing.T) {
	cfg, r, owner, key, path := erasedCarryFixture(t)
	if e := os.WriteFile(filepath.Join(path, "unknown.private"), []byte("retain"), 0600); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := r.CompactExpiredBodyCarry(t.Context(), owner, key); e == nil {
		t.Fatal("unknown file accepted")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("unknown file refusal changed storage")
	}
}

func TestBodyCarrySnapshotRejectsValidCRCChangedOldCarry(t *testing.T) {
	cfg, r, owner, key, path := erasedCarryFixture(t)
	stop := errors.New("retain old WAL for validation")
	b := r.posting[owner]
	b.deletionCheckpoint = func(s string) error {
		if s == "carry_snapshot:switched" {
			return stop
		}
		return nil
	}
	if e := r.CompactExpiredBodyCarry(t.Context(), owner, key); !errors.Is(e, stop) {
		t.Fatal(e)
	}
	b.deletionCheckpoint = nil
	wal := filepath.Join(path, "control-000001.wal")
	changeOldRateCarryCRC(t, wal)
	before := requiredStartupFiles(t, cfg.DataDir)
	if e := r.CompactExpiredBodyCarry(t.Context(), owner, key); e == nil {
		t.Fatal("old carry changed with valid frame CRC was reclaimed")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("changed old WAL refusal mutated files")
	}
}

// changeOldRateCarryCRC は最後の現在値を変えず、過去のcarry値と有効なframe CRCを作り直す。
func changeOldRateCarryCRC(t *testing.T, path string) {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	out := bytes.NewBuffer(append([]byte{}, raw[:64]...))
	input := bytes.NewReader(raw[64:])
	changed := false
	for input.Len() != 0 {
		frame, _, e := store.ReadFrame(input)
		if e != nil {
			t.Fatal(e)
		}
		var op store.ControlOperation
		if e = strictjson.Decode(frame.Records[0].JSON, &op); e != nil {
			t.Fatal(e)
		}
		changed = changeRateMutation(t, &op) || changed
		frame.Records[0].JSON, e = json.Marshal(op)
		if e != nil {
			t.Fatal(e)
		}
		encoded, e := store.EncodeFrame(frame)
		if e != nil {
			t.Fatal(e)
		}
		out.Write(encoded)
	}
	if !changed {
		t.Fatal("no historical rate row changed")
	}
	if e = os.WriteFile(path, out.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
}

func changeRateMutation(t *testing.T, op *store.ControlOperation) bool {
	t.Helper()
	changed := false
	for i := range op.Mutations {
		m := &op.Mutations[i]
		if m.Collection != "rate_carry" || bytes.Equal(m.Value, []byte("null")) {
			continue
		}
		var v app.RateCarry
		if e := strictjson.Decode(m.Value, &v); e != nil {
			t.Fatal(e)
		}
		v.At++
		v.Expires++
		var e error
		m.Value, e = json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		changed = true
	}
	return changed
}
