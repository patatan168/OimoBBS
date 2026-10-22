// 実案件の元予約回収後、現在サイトに束縛した検査/所有者再Openと旧索引拒否を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

func TestRegisteredOptionalHoldRetirementChecksAndReopensCompletedSource(t *testing.T) {
	r, plan, candidate, key, now := optionalRetirementRegistrationFixture(t)
	r.optionalHoldLifecycleMu.Lock()
	r.mu.Lock()
	err := r.registerOptionalHoldRetirementLocked(t.Context(), plan, candidate, now)
	if err == nil {
		err = r.optionalStore.CommitOptionalHoldRetirement(t.Context(), candidate, evidence.OptionalHoldRetirementReader, now, func(got evidence.OptionalHoldRetirementCandidate) error {
			if !reflect.DeepEqual(got, candidate) {
				return store.ErrCorrupt
			}
			return nil
		})
	}
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
	check, err := optionalHoldStartupCheckAt(r.cfg.DataDir, key, site.MinimumReader, false, state, domain.Time(now.UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(r.cfg.DataDir, "reports", "http")
	assertCompletedOptionalSourceOpen(t, root, site, state, key, check, now)
	assertCompletedOptionalSourceRejectsSameSequence(t, root, site, state, candidate, key, check)
	assertCompletedOptionalSourceRejectsOldIndex(t, root, site, state, candidate, key, check)
}

// assertCompletedOptionalSourceRejectsSameSequence は正当署名の同seq別hashでも登録候補以外を拒否する。
func assertCompletedOptionalSourceRejectsSameSequence(t *testing.T, root string, site siteState, state store.ControlState, candidate evidence.OptionalHoldRetirementCandidate, key ed25519.PrivateKey, check func(evidence.OptionalHoldReferences) error) {
	t.Helper()
	body, err := base64.StdEncoding.Strict().DecodeString(candidate.Next.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	var owner domain.ID
	if err := json.Unmarshal(fields["source_owner_id"], &owner); err != nil {
		t.Fatal(err)
	}
	desc, err := evidence.VerifyOptionalHoldIndexEvent(site.ID, key.Public().(ed25519.PublicKey), candidate.Next)
	if err != nil {
		t.Fatal(err)
	}
	fields["recorded_at_ns"], err = json.Marshal(desc.At - 1)
	if err != nil {
		t.Fatal(err)
	}
	body, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := evidence.Seal(evidence.Source{Owner: owner, Seq: uint64(desc.Sequence)}, site.ID, "checkpoint", body, candidate.Next.PreviousSHA, 10, key)
	if err != nil {
		t.Fatal(err)
	}
	assertCompletedOptionalSourceRejectsIndex(t, root, site, state, key, check, changed)
}

func assertCompletedOptionalSourceRejectsIndex(t *testing.T, root string, site siteState, state store.ControlState, key ed25519.PrivateKey, check func(evidence.OptionalHoldReferences) error, event evidence.Event) {
	t.Helper()
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := requiredStartupFiles(t, root)
	s, err := openOptionalSourceChecked(root, site, key, state, check)
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Fatal("unregistered source index accepted")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, root)) {
		t.Fatal("index refusal changed files")
	}
}

func assertCompletedOptionalSourceOpen(t *testing.T, root string, site siteState, state store.ControlState, key ed25519.PrivateKey, check func(evidence.OptionalHoldReferences) error, now time.Time) {
	t.Helper()
	before := requiredStartupFiles(t, root)
	if err := inspectOptionalSourceChecked(root, site, key, state, now, check); err != nil {
		t.Fatal("completed source inspection", err)
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, root)) {
		t.Fatal("inspection changed completed source")
	}
	s, err := openOptionalSourceChecked(root, site, key, state, check)
	if err != nil {
		t.Fatal("completed source reopen", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertCompletedOptionalSourceRejectsOldIndex(t *testing.T, root string, site siteState, state store.ControlState, candidate evidence.OptionalHoldRetirementCandidate, key ed25519.PrivateKey, check func(evidence.OptionalHoldReferences) error) {
	t.Helper()
	path := filepath.Join(root, evidence.OptionalHoldsDirectory, evidence.OptionalHoldIndexFile)
	raw, err := json.Marshal(candidate.Previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	before := requiredStartupFiles(t, root)
	s, err := openOptionalSourceChecked(root, site, key, state, check)
	if s != nil {
		s.Close()
	}
	if err == nil {
		t.Fatal("old index without removed source accepted")
	}
	if !reflect.DeepEqual(before, requiredStartupFiles(t, root)) {
		t.Fatal("old index refusal changed files")
	}
}
