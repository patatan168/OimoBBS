// 元所有者Openより前に現在サイトの全登録を検査し、最新の回収停止点だけを再開する。
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"reflect"
	"time"
)

// resumeOptionalHoldRetirementsAt は起動所有排他内で呼ぶ。新しい予約を持つ索引を過去候補へ戻さない。
func resumeOptionalHoldRetirementsAt(cfg Config, site siteState, state store.ControlState, now time.Time) error {
	if !optionalHoldRetirementEnabled(state) {
		return nil
	}
	seed, key, err := readRetirementKey(cfg.DataDir)
	if err != nil {
		return err
	}
	defer clear(seed)
	defer clear(key)
	registered, err := checkedOptionalRetirementSnapshots(cfg.DataDir, key, state, site, nil, domain.Time(now.UnixNano()))
	if err != nil {
		return err
	}
	root := filepath.Join(cfg.DataDir, "reports", "http")
	current, pending, index, err := readOptionalRetirementStartupIndex(root, site.ID, key.Public().(ed25519.PublicKey), domain.Time(now.UnixNano()))
	if err != nil {
		return err
	}
	if ordinaryOptionalIndexPending(site.ID, key.Public().(ed25519.PublicKey), current, pending) {
		return deferOrdinaryOptionalIndexPending(index, registered)
	}
	selected, err := selectOptionalRetirementStartup(index, pending, registered)
	if err != nil {
		return err
	}
	if selected == nil {
		if pending != nil {
			return nil
		}
		return inspectRetiredOptionalStartupSource(root, site, key, registered, now)
	}
	if optionalRetirementAlreadyUnlinked(root, index, pending, *selected) {
		return store.SyncDirectory(filepath.Join(root, evidence.OptionalHoldsDirectory))
	}
	return resumeSelectedOptionalRetirement(root, site, key, registered, *selected, now)
}

func ordinaryOptionalIndexPending(site domain.ID, key ed25519.PublicKey, current evidence.Event, pending *evidence.Event) bool {
	if pending == nil || pending.EventSHA == current.EventSHA {
		return false
	}
	_, err := evidence.VerifyOptionalHoldRetirementCandidate(site, key, evidence.OptionalHoldRetirementCandidate{Previous: current, Next: *pending})
	return err != nil
}

func readOptionalRetirementStartupIndex(root string, site domain.ID, key ed25519.PublicKey, now domain.Time) (evidence.Event, *evidence.Event, evidence.OptionalHoldIndexDescription, error) {
	current, pending, err := evidence.InspectOptionalHoldIndexFiles(root, site, key)
	if err != nil {
		return current, pending, evidence.OptionalHoldIndexDescription{}, err
	}
	index, err := evidence.VerifyOptionalHoldIndexEvent(site, key, current)
	if err != nil {
		return current, pending, index, err
	}
	return current, pending, index, checkOptionalStartupIndexClock(site, key, index, pending, now)
}

func checkOptionalStartupIndexClock(site domain.ID, key ed25519.PublicKey, index evidence.OptionalHoldIndexDescription, pending *evidence.Event, now domain.Time) error {
	if now < index.At {
		return evidence.ErrRetirementClock
	}
	if pending == nil {
		return nil
	}
	next, err := evidence.VerifyOptionalHoldIndexEvent(site, key, *pending)
	if err != nil {
		return err
	}
	if now < next.At {
		return evidence.ErrRetirementClock
	}
	return nil
}

// deferOrdinaryOptionalIndexPending は検査済み追加/同一候補を通常Openへ渡し、未開始回収との競合を拒否する。
func deferOrdinaryOptionalIndexPending(index evidence.OptionalHoldIndexDescription, registered map[domain.Hash]checkedOptionalRetirement) error {
	selected, err := selectOptionalRetirementStartup(index, nil, registered)
	if err != nil {
		return err
	}
	if selected != nil && selected.Description.Sequence > index.Sequence {
		return store.ErrCorrupt
	}
	return nil
}

func optionalRetirementAlreadyUnlinked(root string, index evidence.OptionalHoldIndexDescription, pending *evidence.Event, row checkedOptionalRetirement) bool {
	if pending != nil || index.Sequence != row.Description.Sequence {
		return false
	}
	_, err := os.Lstat(filepath.Join(root, evidence.OptionalHoldsDirectory, row.Description.Case.String()+".json"))
	return os.IsNotExist(err)
}

func resumeSelectedOptionalRetirement(root string, site siteState, key ed25519.PrivateKey, registered map[domain.Hash]checkedOptionalRetirement, selected checkedOptionalRetirement, now time.Time) error {
	candidate := selected.Registration.candidate()
	if err := evidence.InspectOptionalHoldRetirement(context.Background(), root, site.ID, key, candidate, site.MinimumReader, now); err != nil {
		return err
	}
	if err := evidence.ResumeOptionalHoldRetirement(context.Background(), root, site.ID, key, candidate, site.MinimumReader, now, func(got evidence.OptionalHoldRetirementCandidate) error {
		if !reflect.DeepEqual(got, candidate) {
			return store.ErrCorrupt
		}
		return nil
	}); err != nil {
		return err
	}
	return inspectRetiredOptionalStartupSource(root, site, key, registered, now)
}

// selectOptionalRetirementStartup は全登録の位置を先に検査し、同時に二件の未開始を認めない。
func selectOptionalRetirementStartup(index evidence.OptionalHoldIndexDescription, pending *evidence.Event, rows map[domain.Hash]checkedOptionalRetirement) (*checkedOptionalRetirement, error) {
	var selected *checkedOptionalRetirement
	for _, row := range rows {
		present := index.Sequence < row.Description.Sequence
		if err := checkOptionalRetirementIndexPosition(index, row, present); err != nil {
			return nil, err
		}
		if index.Sequence > row.Description.Sequence {
			continue
		}
		if selected == nil || selected.Description.Sequence < row.Description.Sequence {
			copy := row
			selected = &copy
			continue
		}
		if selected.Description.Sequence == row.Description.Sequence {
			return nil, store.ErrCorrupt
		}
	}
	return selected, checkOptionalStartupPending(index, pending, selected)
}

func checkOptionalStartupPending(index evidence.OptionalHoldIndexDescription, pending *evidence.Event, selected *checkedOptionalRetirement) error {
	if pending == nil {
		return nil
	}
	if selected == nil {
		if pending.EventSHA == index.SHA {
			return nil
		}
		return store.ErrCorrupt
	}
	if !reflect.DeepEqual(*pending, selected.Registration.Next) {
		return store.ErrCorrupt
	}
	return nil
}

func inspectRetiredOptionalStartupSource(root string, site siteState, key ed25519.PrivateKey, registered map[domain.Hash]checkedOptionalRetirement, now time.Time) error {
	return evidence.InspectOptionalStoreRetirementChecked(root, site.ID, key, site.MinimumReader, domain.Time(now.UnixNano()), func(source evidence.OptionalHoldReferences) error {
		rows, err := source.OptionalHoldReceipts()
		if err != nil {
			return err
		}
		_, err = checkedOptionalRetiredSourceAbsence(source, rows, site.ID, key.Public().(ed25519.PublicKey), registered, domain.Time(now.UnixNano()))
		return err
	})
}
