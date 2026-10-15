// 起動排他内で先行登録と現在元を非変更検査し、通常案件を開く前に中断した回収を完了する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"time"
)

// resumeRegisteredCaseRetirements は全対象/現在元の検査後だけ物理回収を再開する。
// 呼出元は起動排他・site/鍵/投稿正本検査を保持する。通常checkからは呼ばない。
func resumeRegisteredCaseRetirements(cfg Config, site siteState, state store.ControlState) error {
	rows, e := caseRetirementRegistrations(state, site)
	if e != nil || len(rows) == 0 {
		return e
	}
	seed, key, e := readRetirementKey(cfg.DataDir)
	if e != nil {
		return e
	}
	defer clear(seed)
	defer clear(key)
	now := time.Now()
	plans, e := inspectRetirementStartupTargets(cfg.DataDir, key, site.MinimumReader, rows, now)
	if e != nil || len(plans) == 0 {
		return e
	}
	required, optional, e := retirementStartupSources(cfg, site, state, key)
	if e != nil {
		return e
	}
	if e = checkRetirementStartupSources(plans, key.Public().(ed25519.PublicKey), required, optional, now); e != nil {
		return e
	}
	for id, row := range plans {
		if e = disclosure.ResumeCaseRetirement(context.Background(), filepath.Join(cfg.DataDir, "cases"), key, id, row.Event, site.MinimumReader, required.Receipts, optional, now); e != nil {
			return e
		}
	}
	return nil
}

// readRetirementKey は既存の私有署名鍵だけを読み、欠落を再作成しない。
func readRetirementKey(root string) ([]byte, ed25519.PrivateKey, error) {
	seed, e := readPrivate(filepath.Join(root, "keys", "evidence-000010.seed"), ed25519.SeedSize)
	if e != nil {
		return nil, nil, e
	}
	return seed, ed25519.NewKeyFromSeed(seed), nil
}

// checkRetirementStartupSources は全対象を照合し、一件目の削除後に別対象の元不一致が判明するのを防ぐ。
func checkRetirementStartupSources(plans map[domain.ID]caseRetirementRegistration, key ed25519.PublicKey, required requiredHoldSourceSnapshots, optional []evidence.OptionalHoldReceipt, now time.Time) error {
	for id, row := range plans {
		intent, e := disclosure.VerifyCaseRetirementIntent(row.Event, row.Fingerprint, key)
		if e != nil {
			return e
		}
		candidate := disclosure.CaseRetirementCandidate{Case: id, Revision: intent.Revision, Head: intent.Head, EligibleAt: intent.EligibleAt, Clock: intent.Clock, RequiredRelease: intent.RequiredRelease, HTTPRelease: intent.HTTPRelease}
		if e = disclosure.CheckCaseRetirementSources(candidate, required.Receipts, optional, domain.Time(now.UnixNano())); e != nil {
			return e
		}
	}
	return nil
}

func inspectRetirementStartupTargets(root string, key ed25519.PrivateKey, reader uint32, rows map[domain.Hash]caseRetirementRegistration, now time.Time) (map[domain.ID]caseRetirementRegistration, error) {
	entries, e := os.ReadDir(filepath.Join(root, "cases"))
	if e != nil {
		return nil, e
	}
	if len(entries) > disclosure.MaxCases*2 {
		return nil, disclosure.ErrLimit
	}
	result := map[domain.ID]caseRetirementRegistration{}
	for _, entry := range entries {
		var id domain.ID
		if json.Unmarshal([]byte(`"`+entry.Name()+`"`), &id) != nil {
			continue
		}
		fingerprint, e := disclosure.CaseRetirementFingerprint(key, id)
		if e != nil {
			return nil, e
		}
		row, found := rows[fingerprint]
		if !found {
			continue
		}
		if e = disclosure.InspectCaseRetirementRemainder(context.Background(), filepath.Join(root, "cases"), key, id, row.Event, reader, now); e != nil {
			return nil, e
		}
		result[id] = row
	}
	return result, nil
}

func retirementStartupSources(cfg Config, site siteState, state store.ControlState, key ed25519.PrivateKey) (requiredHoldSourceSnapshots, []evidence.OptionalHoldReceipt, error) {
	activations, e := requiredHoldActivations(state, site)
	if e != nil {
		return requiredHoldSourceSnapshots{}, nil, e
	}
	if e = inspectRequiredHoldParent(cfg.DataDir, activations, true); e != nil {
		return requiredHoldSourceSnapshots{}, nil, e
	}
	required, e := inspectRequiredHoldSources(cfg.DataDir, activations, key, true, site.MinimumReader)
	if e != nil {
		return required, nil, e
	}
	var optional []evidence.OptionalHoldReceipt
	if _, enabled := state.Rows["optional_http:http"]; enabled {
		if e = inspectOptionalHoldActivation(cfg, site, state, false); e != nil {
			return required, nil, e
		}
		e = evidence.InspectOptionalStoreCheckedClock(filepath.Join(cfg.DataDir, "reports", "http"), site.ID, key, func(source evidence.OptionalHoldReferences) error {
			var e error
			optional, e = source.OptionalHoldReceipts()
			return e
		}, domain.Time(time.Now().UnixNano()))
	}
	return required, optional, e
}
