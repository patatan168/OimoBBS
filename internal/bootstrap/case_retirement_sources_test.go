// 登録署名と元の現在snapshotの解除一致・欠落/差替え拒否・通常案件検査の維持を検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// retirementSourceFixture は実登録を基に、元集合照合専用の署名済み解除hash fixtureを作る。
// 架空metadataは元署名検査の証拠ではなく、所有者検査済みsnapshotを受ける境界の試験にだけ使う。
func retirementSourceFixture(t *testing.T) (store.ControlState, ed25519.PrivateKey, disclosure.CaseRetirementCandidate, disclosure.CaseRetirementIntent) {
	t.Helper()
	cfg, r, candidate := caseRetirementRegistryFixture(t)
	intent := registerRetirementForTest(t, r, candidate)
	seed, e := readPrivate(filepath.Join(cfg.DataDir, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	t.Cleanup(func() { clear(key) })
	intent.RequiredRelease[0] = 1
	intent.HTTPRelease[0] = 2
	payload, e := json.Marshal(intent)
	if e != nil {
		t.Fatal(e)
	}
	event, e := evidence.Seal(evidence.Source{Owner: intent.Owner, Seq: 1}, intent.Owner, "receipt", payload, domain.Hash{}, 10, key)
	if e != nil {
		t.Fatal(e)
	}
	r.mu.Lock()
	state := r.site.State()
	r.mu.Unlock()
	rows := make(map[string]store.ControlRow, len(state.Rows))
	for name, row := range state.Rows {
		rows[name] = row
	}
	name := "case_retirement:" + intent.Fingerprint.String()
	var registration caseRetirementRegistration
	if e = strictjson.Decode(rows[name].Value, &registration); e != nil {
		t.Fatal(e)
	}
	registration.Event = event
	row := rows[name]
	row.Value, e = json.Marshal(registration)
	if e != nil {
		t.Fatal(e)
	}
	rows[name] = row
	for _, name := range []string{"optional_http:http", "optional_holds:http"} {
		raw, e := json.Marshal(optionalLogActivation{Site: registration.Site, Phase: "active"})
		if e != nil {
			t.Fatal(e)
		}
		rows[name] = store.ControlRow{Value: raw}
	}
	state.Rows = rows
	return state, key, candidate, intent
}

func TestRetirementRequiredSourcesRequireCurrentReleaseAndPreserveLiveRows(t *testing.T) {
	state, key, candidate, intent := retirementSourceFixture(t)
	now := domain.Time(time.Now().UnixNano())
	receipt := app.RequiredHoldReceipt{Binding: app.RequiredHoldBinding{Case: candidate.Case}, State: "released", SHA: intent.RequiredRelease, At: intent.At}
	renewal := app.RequiredHoldRenewalReceipt{Original: receipt}
	sources := requiredHoldSourceSnapshots{Receipts: []app.RequiredHoldReceipt{receipt}, Renewals: []app.RequiredHoldRenewalReceipt{renewal}}
	filtered, e := requiredSourcesWithRetirements(state, key, nil, sources, now)
	if e != nil || len(filtered.Receipts) != 0 || len(filtered.Renewals) != 0 {
		t.Fatal("archived release not separated", filtered, e)
	}
	cases := []disclosure.RequiredCaseInspection{{Current: disclosure.Case{ID: candidate.Case}}}
	filtered, e = requiredSourcesWithRetirements(state, key, cases, sources, now)
	if e != nil || !reflect.DeepEqual(filtered, sources) {
		t.Fatal("live case source skipped", filtered, e)
	}
	for _, damage := range []string{"missing", "duplicate", "active", "hash", "future"} {
		t.Run(damage, func(t *testing.T) {
			changed := damagedRetirementRequiredSources(sources, damage, now)
			before := requiredHoldSourceSnapshots{Receipts: append([]app.RequiredHoldReceipt{}, changed.Receipts...), Renewals: changed.Renewals}
			if _, e := requiredSourcesWithRetirements(state, key, nil, changed, now); e == nil {
				t.Fatal("invalid archived source accepted")
			}
			if !reflect.DeepEqual(before.Receipts, changed.Receipts) {
				t.Fatal("rejected inspection mutated source")
			}
		})
	}
}

func damagedRetirementRequiredSources(s requiredHoldSourceSnapshots, damage string, now domain.Time) requiredHoldSourceSnapshots {
	s.Receipts = append([]app.RequiredHoldReceipt{}, s.Receipts...)
	switch damage {
	case "missing":
		s.Receipts = []app.RequiredHoldReceipt{}
	case "duplicate":
		s.Receipts = append(s.Receipts, s.Receipts[0])
	case "active":
		s.Receipts[0].State = "active"
	case "hash":
		s.Receipts[0].SHA[0] ^= 1
	case "future":
		s.Receipts[0].At = now + 1
	}
	return s
}

func TestRetirementOptionalSourcesRequireCurrentReleaseAndPreserveLiveRows(t *testing.T) {
	state, key, candidate, intent := retirementSourceFixture(t)
	now := domain.Time(time.Now().UnixNano())
	intents, e := verifiedRetirementIntents(state, key.Public().(ed25519.PublicKey), now)
	if e != nil {
		t.Fatal(e)
	}
	fingerprint := func(id domain.ID) domain.Hash { hash, _ := disclosure.CaseRetirementFingerprint(key, id); return hash }
	row := evidence.OptionalHoldReceipt{Binding: evidence.OptionalHoldBinding{Case: candidate.Case}, State: "released", SHA: intent.HTTPRelease, At: intent.At}
	for _, damage := range []string{"valid", "live", "missing", "duplicate", "active", "hash", "future"} {
		t.Run(damage, func(t *testing.T) {
			rows := []evidence.OptionalHoldReceipt{row}
			live := map[domain.ID]bool{candidate.Case: damage == "live"}
			rows = damagedRetirementOptionalSources(rows, damage, now)
			filtered, e := optionalSourcesWithRetirements(rows, live, intents, fingerprint, now)
			if damage == "live" {
				if e != nil || !reflect.DeepEqual(filtered, rows) {
					t.Fatal("live source skipped", e)
				}
			} else if damage == "valid" {
				if e != nil || len(filtered) != 0 {
					t.Fatal("archived release not separated", e)
				}
			} else if e == nil {
				t.Fatal("invalid archived source accepted")
			}
		})
	}
}

func damagedRetirementOptionalSources(rows []evidence.OptionalHoldReceipt, damage string, now domain.Time) []evidence.OptionalHoldReceipt {
	switch damage {
	case "missing":
		return nil
	case "duplicate":
		return append(rows, rows[0])
	case "active":
		rows[0].State = "active"
	case "hash":
		rows[0].SHA[0] ^= 1
	case "future":
		rows[0].At = now + 1
	}
	return rows
}

func TestRetirementHTTPReleaseRequiresActiveSourceRegistration(t *testing.T) {
	state, key, _, _ := retirementSourceFixture(t)
	now := domain.Time(time.Now().UnixNano())
	for _, name := range []string{"optional_http:http", "optional_holds:http"} {
		row := state.Rows[name]
		delete(state.Rows, name)
		if _, e := verifiedRetirementIntents(state, key.Public().(ed25519.PublicKey), now); e == nil {
			t.Fatal("missing HTTP activation accepted", name)
		}
		state.Rows[name] = row
	}
}

func TestRetirementOptionalCheckStillRejectsUnregisteredOrphan(t *testing.T) {
	state, key, candidate, intent := retirementSourceFixture(t)
	now := domain.Time(time.Now().UnixNano())
	intents, e := verifiedRetirementIntents(state, key.Public().(ed25519.PublicKey), now)
	if e != nil {
		t.Fatal(e)
	}
	fingerprint := func(id domain.ID) domain.Hash { hash, _ := disclosure.CaseRetirementFingerprint(key, id); return hash }
	rows := []evidence.OptionalHoldReceipt{
		{Binding: evidence.OptionalHoldBinding{Case: candidate.Case}, State: "released", SHA: intent.HTTPRelease, At: intent.At},
		{Binding: evidence.OptionalHoldBinding{Case: domain.NewID()}, State: "released", SHA: intent.HTTPRelease, At: intent.At},
	}
	if e = optionalHoldRetirementCheck(nil, intents, fingerprint, now)(retirementOptionalReferences{rows: rows}); e == nil {
		t.Fatal("unregistered orphan skipped")
	}
}
