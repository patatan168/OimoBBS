// 非必須HTTP列を変更せず検査し、起動時だけ許可される補完と区別する。
package evidence

import (
	"crypto/ed25519"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// InspectOptionalStore は署名・所有者・連続seqを読取り専用で検査する。
// 作成・回収の途中状態はErrIncompleteを返し、正本や候補を削除・補完しない。
func InspectOptionalStore(root string, site domain.ID, key ed25519.PrivateKey) error {
	return inspectOptionalStore(root, site, key, nil, 0, false)
}

// InspectOptionalStoreChecked は案件参照との対応も検査し、予約候補/原本を補完しない。
func InspectOptionalStoreChecked(root string, site domain.ID, key ed25519.PrivateKey, check func(OptionalHoldReferences) error) error {
	if check == nil {
		return store.ErrCorrupt
	}
	return inspectOptionalStore(root, site, key, check, 0, false)
}

// InspectOptionalStoreCheckedClock は物理回収前の読取り検査として全署名時計床も現在時計へ照合する。
// 通常の検査と異なり、未来時刻の有効履歴でも回収を許可しない。
func InspectOptionalStoreCheckedClock(root string, site domain.ID, key ed25519.PrivateKey, check func(OptionalHoldReferences) error, now domain.Time) error {
	if check == nil || now <= 0 {
		return store.ErrCorrupt
	}
	return inspectOptionalStore(root, site, key, check, now, false)
}

// InspectOptionalStoreRetirementChecked は回収対応索引を現在登録へ照合し、候補/原本を変更しない。
func InspectOptionalStoreRetirementChecked(root string, site domain.ID, key ed25519.PrivateKey, reader uint32, now domain.Time, check func(OptionalHoldReferences) error) error {
	if reader < OptionalHoldRetirementReader || check == nil || now <= 0 {
		return store.ErrCorrupt
	}
	return inspectOptionalStore(root, site, key, check, now, true)
}

// inspectOptionalStore は予約集合の読取り照合後に原本の署名と停止点を検査する。
func inspectOptionalStore(root string, site domain.ID, key ed25519.PrivateKey, check func(OptionalHoldReferences) error, now domain.Time, retirementAuthorized bool) error {
	if site == (domain.ID{}) || len(key) != ed25519.PrivateKeySize {
		return store.ErrCorrupt
	}
	info, e := os.Lstat(root)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	s := &OptionalStore{root: root, site: site, owner: OptionalOwner(site), key: key, journals: map[uint64]*Journal{}, retirementAuthorized: retirementAuthorized}
	if e = s.loadOptionalHolds(true); e != nil {
		return e
	}
	if check != nil {
		if e = check(optionalHoldReferences{s}); e != nil {
			return e
		}
	}
	if e = s.resumeOptionalCreations(true); e != nil {
		return e
	}
	if e = s.resumeOptionalCheckpointCandidates(true); e != nil {
		return e
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return e
	}
	if len(entries) > MaxOptionalDays+65 {
		return store.ErrCorrupt
	}
	retired := map[uint64]bool{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		day, err := optionalCheckpointDay(entry.Name())
		if err != nil {
			return err
		}
		if _, err = s.readOptionalCheckpoint(filepath.Join(root, entry.Name()), day); err != nil {
			return err
		}
		retired[day] = true
	}
	days := 0
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == optionalHoldsDir {
			continue
		}
		day, err := strconv.ParseUint(entry.Name(), 10, 64)
		if _, dateErr := time.Parse("20060102", entry.Name()); err != nil || dateErr != nil {
			return store.ErrCorrupt
		}
		dir := filepath.Join(root, entry.Name())
		info, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return store.ErrCorrupt
		}
		if err = inspectOptionalDayNames(dir); err != nil {
			return err
		}
		if retired[day] {
			return store.ErrIncomplete
		}
		if _, err = os.Lstat(filepath.Join(dir, ".optional-prune.snapshot")); err == nil {
			return store.ErrIncomplete
		} else if !os.IsNotExist(err) {
			return err
		}
		j := &Journal{optionalHold: s.holdLive, dir: dir, owner: s.owner, day: day, keyID: 10, key: key, validate: s.validate}
		state, err := store.InspectControl(dir, 8, s.owner, day, j.validateValue)
		if err != nil {
			return err
		}
		if err = j.replayState(state); err != nil {
			return err
		}
		s.journals[day] = j
		days++
	}
	if days > MaxOptionalDays {
		return store.ErrCorrupt
	}
	if e := s.validateOptionalHoldSources(max(s.floor, domain.Time(time.Now().UnixNano()))); e != nil {
		return e
	}
	if e := s.openOptionalCheckpoints(entries, true); e != nil {
		return e
	}
	if now != 0 && now < s.floor {
		return ErrRetirementClock
	}
	return nil
}
