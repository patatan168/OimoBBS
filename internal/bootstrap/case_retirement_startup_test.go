// 実site登録と部分削除から製品起動で回収を完了し、変更した残存fileでは非変更拒否する。
package bootstrap

import (
	"context"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCaseRetirementMaintenanceRegistersRemovesAndReopens(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	c, e := r.evidenceCases.Get(candidate.Case)
	if e != nil {
		t.Fatal(e)
	}
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	e = r.reconcileRequiredRetentionLocked(context.Background())
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	if e != nil {
		t.Fatal("maintenance did not reclaim eligible case", e)
	}
	if _, e = os.Lstat(filepath.Join(cfg.DataDir, "cases", c.ID.String())); !os.IsNotExist(e) {
		t.Fatal("case remained", e)
	}
	checkRetiredCaseCreationRefused(t, r, c)
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil || site.MinimumReader < 51 {
		t.Fatal("reader not persisted", site, e)
	}
	if e = r.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e = Check(cfg); e != nil {
		t.Fatal(e)
	}
	reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if e != nil {
		t.Fatal(e)
	}
	defer reopened.Close()
	checkRetiredCaseCreationRefused(t, reopened, c)
	checkRetirementSlotReusable(t, reopened, c)
}

func TestCaseRetirementStartupResumesPartialRemoval(t *testing.T) {
	for _, point := range []string{"current", "control"} {
		t.Run(point, func(t *testing.T) {
			cfg, r, candidate := caseRetirementRegistryFixture(t)
			registerRetirementForTest(t, r, candidate)
			c, e := r.evidenceCases.Get(candidate.Case)
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Close(); e != nil {
				t.Fatal(e)
			}
			path := filepath.Join(cfg.DataDir, "cases", candidate.Case.String())
			if point == "current" {
				e = os.Remove(filepath.Join(path, "control", "control.current"))
			} else {
				e = os.RemoveAll(filepath.Join(path, "control"))
			}
			if e != nil {
				t.Fatal(e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			if _, e = Check(cfg); e == nil {
				t.Fatal("read-only check accepted pending removal")
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("check changed remainder")
			}
			reopened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if e != nil {
				t.Fatal("partial retirement did not resume", e)
			}
			defer reopened.Close()
			if _, e = os.Lstat(path); !os.IsNotExist(e) {
				t.Fatal("case directory remained", e)
			}
			checkRetiredCaseCreationRefused(t, reopened, c)
			checkRetirementSlotReusable(t, reopened, c)
		})
	}
}

func TestCaseRetirementStartupRefusesChangedPartialRemainder(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	registerRetirementForTest(t, r, candidate)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cfg.DataDir, "cases", candidate.Case.String(), "control")
	if e := os.Remove(filepath.Join(path, "control.current")); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(path, "unknown"), []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if opened != nil {
		_ = opened.Close()
	}
	if e == nil {
		t.Fatal("unknown remainder accepted")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("rejected remainder changed")
	}
}
