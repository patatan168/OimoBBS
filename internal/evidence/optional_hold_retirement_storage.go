// 認可済み索引除去を確定してから解除fileを削除し、停止中は原本GCを拒否する。
package evidence

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// OptionalHoldRetirementReader は回収対応索引を保存する前にサイトへ確定する最低reader。
const OptionalHoldRetirementReader uint32 = 61

// CommitOptionalHoldRetirement は現在サイト登録/物理回収の認可callbackを所有排他内で実行する。
// authorizeは元の公開methodを呼ばず、呼出元は案件lifecycle排他と最低readerの確定を保証する。
// 保存不明やunlink/親Sync失敗ではGCを停止し、専用の認可付き再開を必要とする。
func (s *OptionalStore) CommitOptionalHoldRetirement(ctx context.Context, candidate OptionalHoldRetirementCandidate, reader uint32, now time.Time, authorize func(OptionalHoldRetirementCandidate) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if authorize == nil || s.closed || s.holdsStopped {
		return store.ErrIncomplete
	}
	if reader < OptionalHoldRetirementReader {
		return store.ErrCorrupt
	}
	next, err := s.checkOptionalHoldRetirementCandidate(candidate, now)
	if err != nil {
		return err
	}
	if err := authorize(candidate); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.retirementAuthorized = true
	s.retirementStopped = true
	if err := s.saveOptionalHoldIndexRetirement(next.payload, next.retirement); err != nil {
		return err
	}
	return s.finishOptionalHoldRetirement()
}

// checkOptionalHoldRetirementCandidate は現在集合/解除正本を候補署名へ再束縛する。
func (s *OptionalStore) checkOptionalHoldRetirementCandidate(candidate OptionalHoldRetirementCandidate, now time.Time) (optionalHoldIndexSaved, error) {
	var empty optionalHoldIndexSaved
	if !equalOptionalHoldBytes(candidate.Previous, s.holdIndex.event) {
		return empty, store.ErrCorrupt
	}
	raw, err := json.Marshal(candidate.Next)
	if err != nil {
		return empty, err
	}
	next, err := s.decodeOptionalHoldIndex(raw)
	if err != nil {
		return empty, err
	}
	if next.retirement == nil {
		return empty, store.ErrCorrupt
	}
	if err := validateOptionalHoldIndexNext(s.holdIndex, next); err != nil {
		return empty, err
	}
	if domain.Time(now.UnixNano()) < max(s.floor, next.payload.At) {
		return empty, ErrRetirementClock
	}
	if err := s.checkKnownOptionalRetirement(next.retirement); err != nil {
		return empty, err
	}
	if err := s.checkOptionalRetirementDisk(next.retirement.Case); err != nil {
		return empty, err
	}
	return next, nil
}

// checkKnownOptionalRetirement はメモリの解除正本を署名済み除去対象へ束縛する。
func (s *OptionalStore) checkKnownOptionalRetirement(r *optionalHoldIndexRetirement) error {
	v, found := s.holds[r.Case]
	if !found || v.payload.State != "released" || v.event.EventSHA != r.Release {
		return store.ErrCorrupt
	}
	return nil
}

func (s *OptionalStore) checkKnownOptionalRetiredSource(id domain.ID) error {
	r := s.holdIndex.retirement
	if r == nil || r.Case != id {
		return store.ErrCorrupt
	}
	return s.checkKnownOptionalRetirement(r)
}

// rejectOptionalRetiredFile は署名済み除去対象の残存解除を検査し、途中回収を通常Openへ渡さない。
// fileは削除せず、現在サイトの認可付きfinishまで保持する。
func (s *OptionalStore) rejectOptionalRetiredFile(ids map[domain.ID]bool) error {
	r := s.holdIndex.retirement
	if r == nil || !ids[r.Case] {
		return nil
	}
	if err := s.inspectOptionalRetiredFile(r); err != nil {
		return err
	}
	return store.ErrIncomplete
}

func (s *OptionalStore) inspectOptionalRetiredFile(r *optionalHoldIndexRetirement) error {
	path := s.holdFile(r.Case)
	if _, err := os.Lstat(path + ".pending"); !os.IsNotExist(err) {
		if err != nil {
			return err
		}
		return store.ErrIncomplete
	}
	raw, err := readOptionalPrivate(path, optionalHoldFileLimit)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	v, err := s.decodeOptionalHold(raw, r.Case)
	if err != nil {
		return err
	}
	if v.payload.State != "released" || v.event.EventSHA != r.Release || v.payload.At > s.holdIndex.payload.At {
		return store.ErrCorrupt
	}
	return nil
}

// finishOptionalHoldRetirement は認可と索引確定の後にのみ呼び、最後に親directoryをSyncする。
func (s *OptionalStore) finishOptionalHoldRetirement() error {
	r := s.holdIndex.retirement
	if r == nil {
		return store.ErrCorrupt
	}
	s.holdsStopped = true
	s.retirementStopped = true
	if err := s.inspectOptionalRetiredFile(r); err != nil {
		return err
	}
	if err := os.Remove(s.holdFile(r.Case)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if s.checkpoint != nil {
		if err := s.checkpoint("hold-retirement:unlink"); err != nil {
			return err
		}
	}
	if err := store.SyncDirectory(filepath.Join(s.root, optionalHoldsDir)); err != nil {
		return err
	}
	delete(s.holds, r.Case)
	s.floor = max(s.floor, s.holdIndex.payload.At)
	s.rebuildOptionalHoldIndex()
	s.holdsStopped = false
	s.retirementStopped = false
	return nil
}
