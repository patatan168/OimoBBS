// 登録済み記録の不可変性、最低reader/所有者/時計と起動前の署名照合を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestCaseRetirementRegistrationCannotBeReplacedOrDeleted(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	intent := registerRetirementForTest(t, r, candidate)
	r.mu.Lock()
	defer r.mu.Unlock()
	row := r.site.State().Rows["case_retirement:"+intent.Fingerprint.String()]
	seq := r.site.State().Seq
	before := requiredStartupFiles(t, cfg.DataDir)
	for _, next := range []json.RawMessage{row.Value, json.RawMessage(`null`)} {
		if e := appendControl(r.site, "case_retirement_register", []store.Mutation{{Collection: "case_retirement", Key: intent.Fingerprint.String(), Value: next}}, []string{}); e == nil {
			t.Fatal("immutable retirement row changed")
		}
		if r.site.State().Seq != seq || !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
			t.Fatal("rejected replacement modified storage")
		}
	}
	if e := snapshotSiteValue("case_retirement", intent.Fingerprint.String(), nil, row.Value); e != nil {
		t.Fatal("valid immutable snapshot row rejected", e)
	}
}

func TestCaseRetirementRegistrationRequiresReaderSiteAndNoExpiry(t *testing.T) {
	_, r, candidate := caseRetirementRegistryFixture(t)
	intent := registerRetirementForTest(t, r, candidate)
	var site siteState
	if e := strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	key := "case_retirement:" + intent.Fingerprint.String()
	row := r.site.State().Rows[key]
	for _, damage := range []string{"reader", "site", "expiry"} {
		t.Run(damage, func(t *testing.T) {
			current := site
			modified := row
			switch damage {
			case "reader":
				current.MinimumReader = 50
			case "site":
				current.ID = domain.NewID()
			case "expiry":
				expires := domain.Time(time.Now().Add(time.Hour).UnixNano())
				modified.Expires = &expires
			}
			if _, e := caseRetirementRegistrations(store.ControlState{Rows: map[string]store.ControlRow{key: modified}}, current); e == nil {
				t.Fatal("registration boundary accepted", damage)
			}
		})
	}
}

func TestCaseRetirementBadSignatureOrClockStopsBeforeProductRepair(t *testing.T) {
	for _, damage := range []string{"signature", "future"} {
		t.Run(damage, func(t *testing.T) {
			cfg, r, candidate := caseRetirementRegistryFixture(t)
			writeBadCaseRetirementRegistration(t, r, candidate, damage)
			if e := r.Close(); e != nil {
				t.Fatal(e)
			}
			before := requiredStartupFiles(t, cfg.DataDir)
			opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
			if opened != nil {
				_ = opened.Close()
			}
			want := store.ErrCorrupt
			if damage == "future" {
				want = evidence.ErrRetirementClock
			}
			if !errors.Is(e, want) {
				t.Fatal("bad retirement registry accepted", damage, e)
			}
			if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
				t.Fatal("invalid registry triggered product repair")
			}
			if _, e = Check(cfg); !errors.Is(e, want) {
				t.Fatal("check missed registry refusal", e)
			}
		})
	}
}

func writeBadCaseRetirementRegistration(t *testing.T, r *Repository, candidate disclosure.CaseRetirementCandidate, damage string) {
	t.Helper()
	r.optionalHoldLifecycleMu.Lock()
	defer r.optionalHoldLifecycleMu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if damage == "future" {
		now = now.Add(time.Hour)
	}
	intent, event, e := r.evidenceCases.BuildCaseRetirementIntent(t.Context(), candidate, nil, nil, now)
	if e != nil {
		t.Fatal(e)
	}
	if damage == "signature" {
		event.EventSHA[0] ^= 1
	}
	var site siteState
	if e = strictjson.Decode(r.site.State().Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	site.MinimumReader = caseRetirementReader
	v := caseRetirementRegistration{Schema: caseRetirementRegistrySchema, Site: site.ID, Fingerprint: intent.Fingerprint, Event: event}
	if e = appendControl(r.site, "case_retirement_register", []store.Mutation{mutation("site", "state", site, nil), mutation("case_retirement", intent.Fingerprint.String(), v, nil)}, []string{}); e != nil {
		t.Fatal(e)
	}
}

func TestCaseRetirementRegistryClockAndPublicKey(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	intent := registerRetirementForTest(t, r, candidate)
	state := r.site.State()
	var site siteState
	if e := strictjson.Decode(state.Rows["site:state"].Value, &site); e != nil {
		t.Fatal(e)
	}
	raw, e := readPrivate(filepath.Join(cfg.DataDir, "instance.json"), 4096)
	if e != nil {
		t.Fatal(e)
	}
	var marker instance
	if e = strictjson.Decode(raw, &marker); e != nil {
		t.Fatal(e)
	}
	key := ed25519.PublicKey(marker.SigningPublic[:])
	if e = inspectCaseRetirementRegistry(state, site, key, intent.At); e != nil {
		t.Fatal("registry verification depended on case directory", e)
	}
	if e = inspectCaseRetirementRegistry(state, site, key, intent.At-1); !errors.Is(e, evidence.ErrRetirementClock) {
		t.Fatal("registered clock floor lost", e)
	}
	wrongKey := append(ed25519.PublicKey{}, key...)
	wrongKey[0] ^= 1
	if e = inspectCaseRetirementRegistry(state, site, wrongKey, intent.At); !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("registered signing key changed", e)
	}
}

func TestCaseRetirementChangedInventoryStopsBeforeProductRepair(t *testing.T) {
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	registerRetirementForTest(t, r, candidate)
	if e := r.Close(); e != nil {
		t.Fatal(e)
	}
	header, e := store.EncodeHeader(store.Header{Kind: 9, Owner: candidate.Case, Generation: 7})
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(cfg.DataDir, "cases", candidate.Case.String(), "control", "control-000007.wal")
	if e = os.WriteFile(path, header, 0600); e != nil {
		t.Fatal(e)
	}
	before := requiredStartupFiles(t, cfg.DataDir)
	opened, e := OpenPostingRepository(cfg, postingCaptureFixture)
	if opened != nil {
		_ = opened.Close()
	}
	if !errors.Is(e, store.ErrCorrupt) {
		t.Fatal("changed retirement inventory accepted", e)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, cfg.DataDir)) {
		t.Fatal("changed inventory triggered product repair")
	}
}
