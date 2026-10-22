// 現在サイトの署名候補・案件物理回収・元索引を照合して、回収済み元解除の不在だけを認める。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"slices"
	"time"
)

type checkedOptionalRetirement struct {
	Registration optionalHoldRetirementRegistration
	Description  evidence.OptionalHoldRetirementDescription
}

// optionalHoldRegisteredCheck は現在サイト/秘密鍵で固定したsnapshotから元所有排他内の照合を構成する。
func optionalHoldRegisteredCheck(root string, key ed25519.PrivateKey, state store.ControlState, cases []disclosure.Case, intents map[domain.Hash]disclosure.CaseRetirementIntent, fingerprint func(domain.ID) domain.Hash, now domain.Time) (func(evidence.OptionalHoldReferences) error, error) {
	var site siteState
	if err := strictjson.Decode(state.Rows["site:state"].Value, &site); err != nil {
		return nil, err
	}
	registered, err := checkedOptionalRetirementSnapshots(root, key, state, site, cases, now)
	if err != nil {
		return nil, err
	}
	if len(registered) == 0 {
		return optionalHoldRetirementCheck(cases, intents, fingerprint, now), nil
	}
	public := key.Public().(ed25519.PublicKey)
	live := optionalRetirementLiveCases(cases)
	return func(source evidence.OptionalHoldReferences) error {
		rows, err := source.OptionalHoldReceipts()
		if err != nil {
			return err
		}
		completed, err := checkedOptionalRetiredSourceAbsence(source, rows, site.ID, public, registered, now)
		if err != nil {
			return err
		}
		filtered, err := optionalSourcesWithCompletedRetirements(rows, live, intents, fingerprint, now, completed)
		if err != nil {
			return err
		}
		return optionalHoldCasesCheck(cases)(retirementOptionalReferences{source, filtered})
	}, nil
}

func optionalRetirementLiveCases(cases []disclosure.Case) map[domain.ID]bool {
	live := make(map[domain.ID]bool, len(cases))
	for _, c := range cases {
		live[c.ID] = true
	}
	return live
}

func checkedOptionalRetirementSnapshots(root string, key ed25519.PrivateKey, state store.ControlState, site siteState, cases []disclosure.Case, now domain.Time) (map[domain.Hash]checkedOptionalRetirement, error) {
	rows, err := optionalHoldRetirementRegistrations(state, site)
	if err != nil {
		return nil, err
	}
	originals, err := caseRetirementRegistrations(state, site)
	if err != nil {
		return nil, err
	}
	live := optionalRetirementLiveCases(cases)
	result := map[domain.Hash]checkedOptionalRetirement{}
	for hash, row := range rows {
		desc, err := verifyOptionalHoldRetirementRegistration(row, originals[hash], key.Public().(ed25519.PublicKey), now)
		if err != nil {
			return nil, err
		}
		actual, err := disclosure.CaseRetirementFingerprint(key, desc.Case)
		if err != nil || actual != hash || live[desc.Case] {
			return nil, store.ErrCorrupt
		}
		if err := disclosure.InspectCompletedCaseRetirement(context.Background(), filepath.Join(root, "cases"), key, desc.Case, originals[hash].Event, site.MinimumReader, time.Unix(0, int64(now))); err != nil {
			return nil, err
		}
		result[hash] = checkedOptionalRetirement{row, desc}
	}
	return result, nil
}

// checkedOptionalRetiredSourceAbsence は同じseqの差替えと旧索引を拒否し、未開始の元解除は不在にしない。
func checkedOptionalRetiredSourceAbsence(source evidence.OptionalHoldReferences, rows []evidence.OptionalHoldReceipt, site domain.ID, key ed25519.PublicKey, registered map[domain.Hash]checkedOptionalRetirement, now domain.Time) (map[domain.Hash]bool, error) {
	references, ok := source.(evidence.OptionalHoldIndexReferences)
	if !ok {
		return nil, store.ErrCorrupt
	}
	event, err := references.OptionalHoldIndexEvent()
	if err != nil {
		return nil, err
	}
	index, err := evidence.VerifyOptionalHoldIndexEvent(site, key, event)
	if err != nil {
		return nil, err
	}
	if now < index.At {
		return nil, evidence.ErrRetirementClock
	}
	current := map[domain.ID]bool{}
	for _, row := range rows {
		current[row.Binding.Case] = true
	}
	completed := map[domain.Hash]bool{}
	for hash, row := range registered {
		if err := checkOptionalRetirementIndexPosition(index, row, current[row.Description.Case]); err != nil {
			return nil, err
		}
		if !current[row.Description.Case] {
			completed[hash] = true
		}
	}
	return completed, nil
}

func checkOptionalRetirementIndexPosition(index evidence.OptionalHoldIndexDescription, row checkedOptionalRetirement, present bool) error {
	desc := row.Description
	if present {
		if index.Sequence != desc.Sequence-1 || index.SHA != row.Registration.Previous.EventSHA || !slices.Contains(index.Cases, desc.Case) {
			return store.ErrCorrupt
		}
		return nil
	}
	if index.Sequence < desc.Sequence || slices.Contains(index.Cases, desc.Case) {
		return store.ErrCorrupt
	}
	if index.Sequence == desc.Sequence && index.SHA != row.Registration.Next.EventSHA {
		return store.ErrCorrupt
	}
	return nil
}
