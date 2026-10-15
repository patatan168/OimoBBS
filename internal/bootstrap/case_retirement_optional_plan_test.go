// 枠再利用前の候補選択が登録・現在解除・案件の完全回収を非変更で照合することを検査する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func TestCompletedOptionalHoldPlanRequiresRegisteredPhysicalCompletion(t *testing.T) {
	cfg, r, c, entries, _ := optionalHeldCaseProductFixture(t)
	func() {
		r.optionalHoldLifecycleMu.Lock()
		defer r.optionalHoldLifecycleMu.Unlock()
		r.mu.Lock()
		defer r.mu.Unlock()
		c = completeOptionalRetirementCopy(t, r, c, entries)
		c = closeOptionalRetirementCase(t, r, c)
	}()
	future := time.Unix(0, int64(c.Closed)).Add(180*24*time.Hour + time.Second)
	reclaimActualOptionalCaseAt(t, r, future)
	seed, key, err := readRetirementKey(cfg.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	defer clear(key)
	rows, err := r.optionalStore.OptionalHoldReceipts()
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(cfg.DataDir, "cases")
	r.mu.Lock()
	state := r.site.State()
	r.mu.Unlock()
	before := requiredStartupFiles(t, cfg.DataDir)
	plans, err := planCompletedOptionalHolds(t.Context(), root, key, state, nil, rows, future)
	if err != nil || len(plans) != 1 {
		t.Fatal("completed source not selected", len(plans), err)
	}
	assertCompletedOptionalPlanBinding(t, plans[0], key, c, rows[0])
	assertCompletedOptionalPlanSourceCandidate(t, r.optionalStore, plans[0], future)
	assertCompletedOptionalPlanOwnership(t, plans[0], rows[0])
	assertCompletedOptionalPlanRejectsInvalidInputs(t, root, key, state, c, rows, future)
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("planning modified source or registration")
	}
	assertCompletedOptionalPlanRejectsRemainingDirectory(t, root, key, state, c, rows, future)
}

// assertCompletedOptionalPlanSourceCandidate は実サイト登録から元所有者の非変更署名候補までを照合する。
func assertCompletedOptionalPlanSourceCandidate(t *testing.T, source *evidence.OptionalStore, plan optionalHoldRetirementPlan, now time.Time) {
	t.Helper()
	candidate, err := source.PrepareOptionalHoldRetirement(t.Context(), plan.Released, plan.Fingerprint, plan.Registration.EventSHA, now)
	if err != nil {
		t.Fatal("registered completed case source candidate", err)
	}
	if candidate.Next.PreviousSHA != candidate.Previous.EventSHA || candidate.Next.RecordID != plan.Released.Site || candidate.Next.EventSHA == candidate.Previous.EventSHA {
		t.Fatal("source candidate is not bound to current site index")
	}
	if err := source.CheckOptionalHoldRelease(plan.Released); err != nil {
		t.Fatal("preparation changed current release", err)
	}
}

func assertCompletedOptionalPlanBinding(t *testing.T, plan optionalHoldRetirementPlan, key ed25519.PrivateKey, c disclosure.Case, source evidence.OptionalHoldReceipt) {
	t.Helper()
	intent, err := disclosure.VerifyCaseRetirementIntent(plan.Registration, plan.Fingerprint, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Fingerprint != rFingerprintForPlan(t, key, c) || intent.HTTPRelease != source.SHA || !reflect.DeepEqual(plan.Released, source) {
		t.Fatal("plan is not bound to registered current release")
	}
}

func rFingerprintForPlan(t *testing.T, key ed25519.PrivateKey, c disclosure.Case) domain.Hash {
	t.Helper()
	hash, err := disclosure.CaseRetirementFingerprint(key, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func assertCompletedOptionalPlanOwnership(t *testing.T, plan optionalHoldRetirementPlan, source evidence.OptionalHoldReceipt) {
	t.Helper()
	old := source.Items[0].Record
	defer func() { source.Items[0].Record = old }()
	source.Items[0].Record = domain.NewID()
	if plan.Released.Items[0].Record != old {
		t.Fatal("source snapshot aliases plan")
	}
}

func assertCompletedOptionalPlanRejectsInvalidInputs(t *testing.T, root string, key ed25519.PrivateKey, state store.ControlState, c disclosure.Case, rows []evidence.OptionalHoldReceipt, now time.Time) {
	t.Helper()
	live, err := planCompletedOptionalHolds(t.Context(), root, key, state, []disclosure.Case{c}, rows, now)
	if err != nil || len(live) != 0 {
		t.Fatal("existing case selected", err)
	}
	changed := append([]evidence.OptionalHoldReceipt{}, rows...)
	changed[0].SHA[0] ^= 1
	if _, err := planCompletedOptionalHolds(t.Context(), root, key, state, nil, changed, now); err == nil {
		t.Fatal("changed source accepted")
	}
	if _, err := planCompletedOptionalHolds(t.Context(), root, key, state, nil, nil, now); err == nil {
		t.Fatal("missing source accepted")
	}
	if _, err := planCompletedOptionalHolds(t.Context(), root, key, state, nil, rows, now.Add(-2*time.Second)); !errors.Is(err, evidence.ErrRetirementClock) {
		t.Fatal("registration clock rollback accepted", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := planCompletedOptionalHolds(ctx, root, key, state, nil, rows, now); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled planning accepted", err)
	}
}

func assertCompletedOptionalPlanRejectsRemainingDirectory(t *testing.T, root string, key ed25519.PrivateKey, state store.ControlState, c disclosure.Case, rows []evidence.OptionalHoldReceipt, now time.Time) {
	t.Helper()
	path := filepath.Join(root, c.ID.String(), "control")
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	before := requiredStartupFiles(t, root)
	plans, err := planCompletedOptionalHolds(t.Context(), root, key, state, nil, rows, now)
	if err != nil || len(plans) != 0 {
		t.Fatal("partly removed case selected", len(plans), err)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, root)) {
		t.Fatal("planning removed remaining directory")
	}
}
