// 現在サイト登録から四保存状態の起動再開と固定再送を実HTTP元fileで検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestRegisteredOptionalHoldRetirementStartupResumesFourStates(t *testing.T) {
	for _, phase := range []string{"not-started", "sync", "rename", "unlink"} {
		t.Run(phase, func(t *testing.T) {
			r, plan, candidate, key, now := optionalRetirementRegistrationFixture(t)
			r.optionalHoldLifecycleMu.Lock()
			r.mu.Lock()
			err := r.registerOptionalHoldRetirementLocked(t.Context(), plan, candidate, now)
			state := r.site.State()
			r.mu.Unlock()
			r.optionalHoldLifecycleMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			var site siteState
			if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(r.cfg.DataDir, "reports", "http")
			prepareOptionalStartupPhase(t, root, candidate, plan, phase)
			inspectOptionalStartupPhase(t, root, site, key, candidate, now)
			if err := resumeOptionalHoldRetirementsAt(r.cfg, site, state, now); err != nil {
				t.Fatal("startup resume", err)
			}
			after := requiredStartupFiles(t, root)
			if err := resumeOptionalHoldRetirementsAt(r.cfg, site, state, now); err != nil {
				t.Fatal("startup replay", err)
			}
			if !reflect.DeepEqual(after, requiredStartupFiles(t, root)) {
				t.Fatal("startup replay changed source")
			}
			check, err := optionalHoldStartupCheckAt(r.cfg.DataDir, key, site.MinimumReader, false, state, domain.Time(now.UnixNano()))
			if err != nil {
				t.Fatal(err)
			}
			assertCompletedOptionalSourceOpen(t, root, site, state, key, check, now)
		})
	}
}

func inspectOptionalStartupPhase(t *testing.T, root string, site siteState, key ed25519.PrivateKey, candidate evidence.OptionalHoldRetirementCandidate, now time.Time) {
	t.Helper()
	before := requiredStartupFiles(t, root)
	if err := evidence.InspectOptionalHoldRetirement(t.Context(), root, site.ID, key, candidate, site.MinimumReader, now); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, root)) {
		t.Fatal("inspection changed phase")
	}
}

func prepareOptionalStartupPhase(t *testing.T, root string, candidate evidence.OptionalHoldRetirementCandidate, plan optionalHoldRetirementPlan, phase string) {
	t.Helper()
	if phase == "not-started" {
		return
	}
	raw, err := json.Marshal(candidate.Next)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile)
	if phase == "sync" {
		path += ".pending"
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if phase == "unlink" {
		if err := os.Remove(filepath.Join(root, evidence.OptionalHoldsDirectory, plan.Released.Binding.Case.String()+".json")); err != nil {
			t.Fatal(err)
		}
	}
}
