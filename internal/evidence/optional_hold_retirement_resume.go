// 現在サイトに認可された同一署名候補だけを停止点から再開し、別予約の欠落を先に拒否する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// ResumeOptionalHoldRetirement は元所有者を閉じた状態で、呼出元の所有排他の下で再開する。
// authorizeは現在サイト登録/案件回収完了を検査する読取り専用callback。nilや旧readerは拒否する。
// 署名候補・現正本・全予約fileを認可前に照合し、不一致では変更しない。原本journalのGCは行わない。
func ResumeOptionalHoldRetirement(ctx context.Context, root string, site domain.ID, key ed25519.PrivateKey, candidate OptionalHoldRetirementCandidate, reader uint32, now time.Time, authorize func(OptionalHoldRetirementCandidate) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if site == (domain.ID{}) || len(key) != ed25519.PrivateKeySize || reader < OptionalHoldRetirementReader || authorize == nil {
		return store.ErrCorrupt
	}
	s := &OptionalStore{root: root, site: site, key: slices.Clone(key)}
	defer clear(s.key)
	next, err := s.inspectOptionalRetirementResume(candidate, now)
	if err != nil {
		return err
	}
	if err := authorize(candidate); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.installResumedOptionalRetirement(candidate); err != nil {
		return err
	}
	s.holdIndex = next
	return s.finishOptionalHoldRetirement()
}

func (s *OptionalStore) decodeOptionalRetirementEvent(event Event) (optionalHoldIndexSaved, error) {
	raw, err := json.Marshal(event)
	if err != nil {
		return optionalHoldIndexSaved{}, err
	}
	return s.decodeOptionalHoldIndex(raw)
}

// inspectOptionalRetirementResume は前後署名、現正本、候補、現存全集合の一致を先行検査する。
func (s *OptionalStore) inspectOptionalRetirementResume(candidate OptionalHoldRetirementCandidate, now time.Time) (optionalHoldIndexSaved, error) {
	previous, err := s.decodeOptionalRetirementEvent(candidate.Previous)
	if err != nil {
		return optionalHoldIndexSaved{}, err
	}
	next, err := s.decodeOptionalRetirementEvent(candidate.Next)
	if err != nil {
		return next, err
	}
	if next.retirement == nil {
		return next, store.ErrCorrupt
	}
	if err := validateOptionalHoldIndexNext(previous, next); err != nil {
		return next, err
	}
	if domain.Time(now.UnixNano()) < max(previous.payload.At, next.payload.At) {
		return next, ErrRetirementClock
	}
	installed, err := s.inspectOptionalRetirementIndexFiles(candidate)
	if err != nil {
		return next, err
	}
	if err := s.inspectOptionalRetirementResumeSources(previous, next, installed, domain.Time(now.UnixNano())); err != nil {
		return next, err
	}
	return next, nil
}

// inspectOptionalRetirementIndexFiles は未設置なら完全候補を必須にし、異なる正本/候補を拒否する。
func (s *OptionalStore) inspectOptionalRetirementIndexFiles(candidate OptionalHoldRetirementCandidate) (bool, error) {
	path := filepath.Join(s.root, optionalHoldsDir, optionalHoldIndexFile)
	raw, err := readOptionalPrivate(path, optionalHoldFileLimit)
	if err != nil {
		return false, err
	}
	current, err := s.decodeOptionalHoldIndex(raw)
	if err != nil {
		return false, err
	}
	installed := equalOptionalHoldBytes(current.event, candidate.Next)
	if !installed && !equalOptionalHoldBytes(current.event, candidate.Previous) {
		return false, store.ErrCorrupt
	}
	raw, err = readOptionalPrivate(path+".pending", optionalHoldFileLimit)
	if os.IsNotExist(err) {
		return installed, nil
	}
	if err != nil {
		return false, err
	}
	pending, err := s.decodeOptionalHoldIndex(raw)
	if err != nil {
		return false, err
	}
	if !equalOptionalHoldBytes(pending.event, candidate.Next) {
		return false, store.ErrCorrupt
	}
	return installed, nil
}

// inspectOptionalRetirementResumeSources は除去対象以外の全fileを署名検査してから削除を許す。
func (s *OptionalStore) inspectOptionalRetirementResumeSources(previous, next optionalHoldIndexSaved, installed bool, now domain.Time) error {
	dir := filepath.Join(s.root, optionalHoldsDir)
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(files) > MaxOptionalHolds+2 {
		return store.ErrCorrupt
	}
	expected := optionalRetirementExpectedFiles(previous.payload.Cases)
	for _, file := range files {
		if file.Name() == optionalHoldIndexFile || file.Name() == optionalHoldIndexFile+".pending" {
			continue
		}
		id, found := expected[file.Name()]
		if !found {
			return store.ErrCorrupt
		}
		if err := s.inspectOptionalRetirementResumeSource(id, next, now); err != nil {
			return err
		}
		delete(expected, file.Name())
	}
	if installed {
		delete(expected, next.retirement.Case.String()+".json")
	}
	if len(expected) != 0 {
		return store.ErrCorrupt
	}
	return nil
}

func optionalRetirementExpectedFiles(cases []domain.ID) map[string]domain.ID {
	expected := make(map[string]domain.ID, len(cases))
	for _, id := range cases {
		expected[id.String()+".json"] = id
	}
	return expected
}

func (s *OptionalStore) inspectOptionalRetirementResumeSource(id domain.ID, next optionalHoldIndexSaved, now domain.Time) error {
	raw, err := readOptionalPrivate(s.holdFile(id), optionalHoldFileLimit)
	if err != nil {
		return err
	}
	v, err := s.decodeOptionalHold(raw, id)
	if err != nil {
		return err
	}
	if v.payload.At > now {
		return ErrRetirementClock
	}
	r := next.retirement
	if id == r.Case && (v.payload.State != "released" || v.event.EventSHA != r.Release || v.payload.At > next.payload.At) {
		return store.ErrCorrupt
	}
	return nil
}

// installResumedOptionalRetirement は検査/認可後だけ、完全候補の設置または同一候補の掃除を行う。
func (s *OptionalStore) installResumedOptionalRetirement(candidate OptionalHoldRetirementCandidate) error {
	installed, err := s.inspectOptionalRetirementIndexFiles(candidate)
	if err != nil {
		return err
	}
	path := filepath.Join(s.root, optionalHoldsDir, optionalHoldIndexFile)
	if !installed {
		if err := s.stageResumedOptionalRetirement(path, candidate.Next); err != nil {
			return err
		}
		return s.installOptionalHoldIndexCandidate(path)
	}
	if err := os.Remove(path + ".pending"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// stageResumedOptionalRetirement は未開始の候補だけを認可済みbytesで作成し、既存候補を上書きしない。
func (s *OptionalStore) stageResumedOptionalRetirement(path string, next Event) error {
	if _, err := os.Lstat(path + ".pending"); !os.IsNotExist(err) {
		return err
	}
	if err := optionalDirectoryCapacity(s.root, 2*optionalHoldFileLimit); err != nil {
		return err
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return s.syncOptionalHoldIndexCandidate(path, raw)
}
