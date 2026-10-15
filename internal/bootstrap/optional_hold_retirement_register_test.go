// 実HTTP案件回収から元索引候補のサイト先行登録・固定再送・現在署名照合までを検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func optionalRetirementRegistrationFixture(t *testing.T) (*Repository, optionalHoldRetirementPlan, evidence.OptionalHoldRetirementCandidate, ed25519.PrivateKey, time.Time) {
	t.Helper()
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	c = completeOptionalRetirementCopy(t, r, c, entries)
	c = closeOptionalRetirementCase(t, r, c)
	r.mu.Unlock()
	r.optionalHoldLifecycleMu.Unlock()
	now := time.Unix(0, int64(c.Closed)).Add(180*24*time.Hour + time.Second)
	reclaimActualOptionalCaseAt(t, r, now)
	seed, key, err := readRetirementKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	clear(seed)
	t.Cleanup(func() { clear(key) })
	rows, err := r.optionalStore.OptionalHoldReceipts()
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	state := r.site.State()
	r.mu.Unlock()
	plans, err := planCompletedOptionalHolds(t.Context(), filepath.Join(cfg.DataDir, "cases"), key, state, nil, rows, now)
	if err != nil || len(plans) != 1 {
		t.Fatal("plan", err)
	}
	plan := plans[0]
	candidate, err := r.optionalStore.PrepareOptionalHoldRetirement(t.Context(), plan.Released, plan.Fingerprint, plan.Registration.EventSHA, now)
	if err != nil {
		t.Fatal(err)
	}
	return r, plan, candidate, key, now
}

func TestOptionalHoldRetirementSiteRegistrationBindsSignedCandidateAndReplays(t *testing.T) {
	r, plan, candidate, key, now := optionalRetirementRegistrationFixture(t)
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	before := requiredStartupFiles(t, filepath.Join(r.cfg.DataDir, "reports", "http"))
	if err := r.registerOptionalHoldRetirementLocked(t.Context(), plan, candidate, now); err != nil {
		t.Fatal(err)
	}
	state := r.site.State()
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		t.Fatal(err)
	}
	assertOptionalRetirementStoredCandidate(t, state, site, plan.Fingerprint, candidate)
	assertOptionalRetirementRegistrationOrder(t, state, site, key, candidate)
	assertOptionalRetirementRegistryDisk(t, r.cfg.DataDir, state, site, key, now)
	if err := inspectCaseRetirementRegistry(state, site, key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if err := r.registerOptionalHoldRetirementLocked(t.Context(), plan, candidate, now); err != nil {
		t.Fatal("replay", err)
	}
	if r.site.State().Seq != state.Seq || !reflect.DeepEqual(before, requiredStartupFiles(t, filepath.Join(r.cfg.DataDir, "reports", "http"))) {
		t.Fatal("registration replay changed source or site sequence")
	}
	assertOptionalRetirementRegistryRejects(t, state, site, key, plan, now)
}

func assertOptionalRetirementRegistrationOrder(t *testing.T, state store.ControlState, site siteState, key ed25519.PrivateKey, candidate evidence.OptionalHoldRetirementCandidate) {
	t.Helper()
	desc, err := evidence.VerifyOptionalHoldRetirementCandidate(site.ID, key.Public().(ed25519.PublicKey), candidate)
	if err != nil {
		t.Fatal(err)
	}
	desc.Fingerprint[0] ^= 1
	if err := checkOptionalRetirementRegistrationProgress(state, site, key.Public().(ed25519.PublicKey), desc); !errors.Is(err, store.ErrCorrupt) {
		t.Fatal("conflicting registration sequence accepted", err)
	}
}

func assertOptionalRetirementRegistryDisk(t *testing.T, root string, state store.ControlState, site siteState, key ed25519.PrivateKey, now time.Time) {
	t.Helper()
	disk, err := inspectRuntimeControl(root, "site", site.ID)
	if err != nil {
		t.Fatal("durable registry read", err)
	}
	if disk.Seq != state.Seq || !reflect.DeepEqual(disk.Rows, state.Rows) {
		t.Fatal("registry disk differs from current state")
	}
	if err := inspectCaseRetirementRegistry(disk, site, key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano())); err != nil {
		t.Fatal(err)
	}
}

func assertOptionalRetirementRegistryRejects(t *testing.T, state store.ControlState, site siteState, key ed25519.PrivateKey, plan optionalHoldRetirementPlan, now time.Time) {
	t.Helper()
	if err := inspectOptionalHoldRetirementRegistry(state, site, key.Public().(ed25519.PublicKey), domain.Time(now.Add(-time.Second).UnixNano())); !errors.Is(err, evidence.ErrRetirementClock) {
		t.Fatal("clock rollback accepted", err)
	}
	for _, change := range []string{"reader", "missing-original", "signature", "expiry"} {
		copyState := state
		copyState.Rows = copyRetirementRegistryRows(state.Rows)
		copySite := site
		name := optionalHoldRetirementCollection + ":" + plan.Fingerprint.String()
		row := copyState.Rows[name]
		switch change {
		case "reader":
			copySite.MinimumReader--
		case "missing-original":
			delete(copyState.Rows, "case_retirement:"+plan.Fingerprint.String())
		case "signature":
			v, err := decodeOptionalHoldRetirementRegistration(plan.Fingerprint.String(), row.Value)
			if err != nil {
				t.Fatal(err)
			}
			v.Next.EventSHA[0] ^= 1
			row.Value, _ = json.Marshal(v)
			copyState.Rows[name] = row
		case "expiry":
			at := domain.Time(now.UnixNano())
			row.Expires = &at
			copyState.Rows[name] = row
		}
		if err := inspectOptionalHoldRetirementRegistry(copyState, copySite, key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano())); err == nil {
			t.Fatal("invalid registry accepted", change)
		}
	}
}

func copyRetirementRegistryRows(rows map[string]store.ControlRow) map[string]store.ControlRow {
	result := make(map[string]store.ControlRow, len(rows))
	for name, row := range rows {
		result[name] = row
	}
	return result
}

func assertOptionalRetirementStoredCandidate(t *testing.T, state store.ControlState, site siteState, hash domain.Hash, candidate evidence.OptionalHoldRetirementCandidate) {
	t.Helper()
	if site.MinimumReader != evidence.OptionalHoldRetirementReader {
		t.Fatal("reader not atomically registered", site.MinimumReader)
	}
	rows, err := optionalHoldRetirementRegistrations(state, site)
	if err != nil || len(rows) != 1 || !reflect.DeepEqual(rows[hash].candidate(), candidate) {
		t.Fatal("candidate changed", err)
	}
}
