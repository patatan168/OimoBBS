// 正しい旧署名を持つ案件作成時点の正本へ戻しても、先行登録と不一致なら起動前に拒否する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"errors"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCaseRetirementOldSignedCaseStopsBeforeProductRepair(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	registerRetirementForTest(t, r, candidate)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	restoreFirstSignedCaseFrame(t, cfg, candidate)
	before := requiredStartupFiles(t, cfg.DataDir)
	opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(e, disclosure.ErrRevision) && !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("old signed case bypassed registration", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("case rollback triggered product repair")
	}
	if _, e = Check(cfg); !errors.Is(e, disclosure.ErrRevision) {
		t.Fatal("check accepted old signed case", e)
	}
}

func restoreFirstSignedCaseFrame(t *testing.T, cfg Config, candidate disclosure.CaseRetirementCandidate) {
	t.Helper()
	control := filepath.Join(cfg.DataDir, "cases", candidate.Case.String(), "control")
	raw, e := os.ReadFile(filepath.Join(control, "control-000001.wal"))
	if e != nil {
		t.Fatal(e)
	}
	h, e := store.DecodeHeader(raw[:64])
	if e != nil {
		t.Fatal(e)
	}
	frames, _, e := store.ReadWALBlock(bytes.NewReader(raw[64:]))
	if e != nil || len(frames) != 1 {
		t.Fatal("first WAL block", e)
	}
	encoded, e := store.EncodeFrame(frames[0])
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(candidateParent(t), "old-control")
	// 元の署名済みframeをそのまま保存する。起動側は通常の案件検証器で署名も検証する。
	old, e := store.CreateControl(path, h, encoded, func(string, string, json.RawMessage, json.RawMessage) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = old.Close(); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"control.current", "control-000001.wal"} {
		restoreRetirementControlFile(t, filepath.Join(path, name), filepath.Join(control, name))
	}
}

func restoreRetirementControlFile(t *testing.T, from, to string) {
	t.Helper()
	raw, e := os.ReadFile(from)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(to, raw, 0600); e != nil {
		t.Fatal(e)
	}
}
