// 非必須HTTP記録を独立した所有列の日別署名journalへ保存し、固定期限で回収する。
package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

const MaxOptionalStoreBytes = 128 << 20
const MaxOptionalDays = 16

// 実保存量と現在行の展開量に別々に適用し、snapshot 64MiBと全日合計128MiBの境界を守る。
const MaxOptionalDayBytes = 64 << 20

// OptionalStore は日別非必須ログ専用。必須投稿の板列とcase領域を共有しない。
type OptionalStore struct {
	mu                   sync.Mutex
	root                 string
	site, owner          domain.ID
	key                  ed25519.PrivateKey
	journals             map[uint64]*Journal
	closed               bool
	cleanupFailed        bool
	floor                domain.Time
	checkpoint           func(string) error
	startupDiscarded     uint64
	holds                map[domain.ID]optionalHoldSaved
	holdIndex            optionalHoldIndexSaved
	heldUntil            map[domain.ID]domain.Time
	holdsStopped         bool
	retirementAuthorized bool
	retirementStopped    bool
	holdProtections      map[domain.ID]optionalHoldProtection
}

// OptionalOwner は必須投稿のsite所有単位と重ならない、非必須専用の固定所有者を返す。
func OptionalOwner(site domain.ID) domain.ID {
	input := append([]byte("oimo/optional-http-owner/v1"), site[:]...)
	h := sha256.Sum256(input)
	var id domain.ID
	copy(id[:], h[:16])
	if id == (domain.ID{}) {
		id[15] = 1
	}
	return id
}

// OpenOptionalStore は既存の固定日別集合を署名照合して開く。初期root作成は呼出元の責務。
func OpenOptionalStore(root string, site domain.ID, key ed25519.PrivateKey) (*OptionalStore, error) {
	return openOptionalStore(root, site, key, nil, false)
}

// OpenOptionalStoreChecked は予約候補補完後・原本の作成/回収復旧前に案件署名参照を検査する。
// checkはmetadataだけを受け取り、拒否時は原本/回収候補を変更しない。nilは拒否する。
func OpenOptionalStoreChecked(root string, site domain.ID, key ed25519.PrivateKey, check func(OptionalHoldReferences) error) (*OptionalStore, error) {
	if check == nil {
		return nil, store.ErrCorrupt
	}
	return openOptionalStore(root, site, key, check, false)
}

// OpenOptionalStoreRetirementChecked はreader61/現在登録の照合callbackを必須にして回収対応索引を開く。
// 回収途中の候補/fileは補完せず拒否する。サイトの専用再開を先に完了させる。
func OpenOptionalStoreRetirementChecked(root string, site domain.ID, key ed25519.PrivateKey, reader uint32, check func(OptionalHoldReferences) error) (*OptionalStore, error) {
	if reader < OptionalHoldRetirementReader || check == nil {
		return nil, store.ErrCorrupt
	}
	return openOptionalStore(root, site, key, check, true)
}

// openOptionalStore は予約の検査を先行し、許可された原本の停止点だけを再開する。
func openOptionalStore(root string, site domain.ID, key ed25519.PrivateKey, check func(OptionalHoldReferences) error, retirementAuthorized bool) (*OptionalStore, error) {
	if site == (domain.ID{}) || len(key) != ed25519.PrivateKeySize {
		return nil, store.ErrCorrupt
	}
	info, e := os.Lstat(root)
	if e != nil {
		return nil, e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, store.ErrCorrupt
	}
	s := &OptionalStore{root: root, site: site, owner: OptionalOwner(site), key: append(ed25519.PrivateKey{}, key...), journals: map[uint64]*Journal{}, retirementAuthorized: retirementAuthorized}
	if e = s.loadOptionalHolds(false); e != nil {
		s.Close()
		return nil, e
	}
	if check != nil {
		if e = check(optionalHoldReferences{s}); e != nil {
			s.Close()
			return nil, e
		}
	}
	if e = s.resumeOptionalCreations(false); e != nil {
		s.Close()
		return nil, e
	}
	if e = s.resumeOptionalCheckpointCandidates(false); e != nil {
		s.Close()
		return nil, e
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		s.Close()
		return nil, e
	}
	if len(entries) > MaxOptionalDays+65 {
		s.Close()
		return nil, errors.New("optional day capacity exceeded")
	}
	retired := map[uint64]optionalCheckpoint{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		day, err := optionalCheckpointDay(entry.Name())
		if err != nil {
			s.Close()
			return nil, err
		}
		p, err := s.readOptionalCheckpoint(filepath.Join(root, entry.Name()), day)
		if err != nil {
			s.Close()
			return nil, err
		}
		retired[day] = p
		s.floor = max(s.floor, p.At)
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == optionalHoldsDir {
			continue
		}
		day, err := strconv.ParseUint(entry.Name(), 10, 64)
		if err != nil || !entry.IsDir() || len(entry.Name()) != 8 || strconv.FormatUint(day, 10) != entry.Name() {
			s.Close()
			return nil, store.ErrCorrupt
		}
		if _, ok := retired[day]; ok {
			if err = removeRetiredOptionalDirectory(filepath.Join(root, entry.Name())); err != nil {
				s.Close()
				return nil, err
			}
			continue
		}
		if err = inspectOptionalDayNames(filepath.Join(root, entry.Name())); err != nil {
			s.Close()
			return nil, err
		}
		j, err := OpenJournal(filepath.Join(root, entry.Name()), s.owner, day, 10, s.key, s.validate)
		if err != nil {
			s.Close()
			return nil, err
		}
		s.journals[day] = j
		j.create = s.createOptionalControl
		j.optionalHold = s.holdLive
	}
	if e = s.openOptionalCheckpoints(entries, false); e != nil {
		s.Close()
		return nil, e
	}
	if len(s.journals) > MaxOptionalDays {
		s.Close()
		return nil, store.ErrCorrupt
	}
	if e := s.validateOptionalHoldSources(max(s.floor, domain.Time(time.Now().UnixNano()))); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}

// inspectOptionalDayNames は独立ログの既知artifactだけを許可し、未知fileを起動で補完しない。
func inspectOptionalDayNames(dir string) error {
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	if len(entries) > 64 {
		return store.ErrCorrupt
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != "control.current" && name != ".optional-prune.snapshot" && optionalControlName.FindString(name) == "" {
			return store.ErrCorrupt
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return store.ErrCorrupt
		}
	}
	return nil
}

func (s *OptionalStore) validate(kind string, raw []byte) error {
	if e := ValidateOptionalPayload(kind, raw); e != nil {
		return e
	}
	var p OptionalPayload
	if json.Unmarshal(raw, &p) != nil || p.Record.Site != s.site || p.Owner != s.owner {
		return store.ErrCorrupt
	}
	day, e := strconv.ParseUint(time.Unix(0, int64(p.Record.Received)).UTC().Format("20060102"), 10, 64)
	if e != nil || uint64(p.Day) != day {
		return store.ErrCorrupt
	}
	return nil
}

// Write は受付時刻の日別正本へWrite/Syncする。失敗は非必須キューの欠測にだけ反映する。
func (s *OptionalStore) Write(ctx context.Context, record OptionalRecord) error {
	return s.WriteBatch(ctx, []OptionalRecord{record})[0]
}

// WriteBatchは日別の連続区間ごとにまとめて同期し、各行の耐久保存結果を返す。
// 日の初回は既存の作成intentで単独保存し、取消・失敗時も既存の復旧手順を保つ。
func (s *OptionalStore) WriteBatch(ctx context.Context, records []OptionalRecord) []error {
	results := make([]error, len(records))
	if len(records) == 0 {
		return results
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for start := 0; start < len(records); {
		end := start + 1
		day := time.Unix(0, int64(records[start].Received)).UTC().Format("20060102")
		for end < len(records) && end-start < MaxOptionalBatch && time.Unix(0, int64(records[end].Received)).UTC().Format("20060102") == day {
			end++
		}
		parsedDay, _ := strconv.ParseUint(day, 10, 64)
		if j := s.journals[parsedDay]; j == nil || j.log == nil {
			end = start + 1
		}
		count, reservation, e := optionalBatchPrefix(records[start:end])
		end = start + count
		batch := records[start:end]
		if e == nil {
			e = s.writeOptionalBatch(ctx, batch, reservation)
		}
		for i := start; i < end; i++ {
			results[i] = e
		}
		start = end
	}
	return results
}

// writeOptionalBatchはStore排他内で同日の検証・容量予約・保存を行う。
func (s *OptionalStore) writeOptionalBatch(ctx context.Context, records []OptionalRecord, reservation int64) error {
	record := records[0]
	for _, r := range records {
		if e := r.Validate(); e != nil {
			return e
		}
		if r.Site != s.site || r.Until <= domain.Time(time.Now().UnixNano()) {
			return store.ErrCorrupt
		}
	}
	if s.closed {
		return errors.New("optional store closed")
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	now := domain.Time(time.Now().UnixNano())
	if now < s.floor {
		return store.ErrCorrupt
	}
	day, e := strconv.ParseUint(time.Unix(0, int64(record.Received)).UTC().Format("20060102"), 10, 64)
	if e != nil {
		return e
	}
	// 終端checkpointが確定したsourceは、同じ日/seqで新しい列を作らない。
	if _, err := os.Lstat(filepath.Join(s.root, fmt.Sprintf("%d.checkpoint.json", day))); err == nil {
		return store.ErrCorrupt
	} else if !os.IsNotExist(err) {
		return err
	}
	dayPath := filepath.Join(s.root, fmt.Sprint(day))
	// 領域上限は実際に増えるframe bytesで判定する。共通余力の保守的な予約とは分ける。
	capacity := func(size int64) error {
		if e := optionalDirectoryCapacity(s.root, size); e != nil {
			return e
		}
		if e := optionalDirectoryCapacityLimit(dayPath, size, MaxOptionalDayBytes); e != nil && !os.IsNotExist(e) {
			return e
		}
		return nil
	}
	j := s.journals[day]
	if j != nil && j.stopped {
		if j.optionalReclaimPending {
			return store.ErrIncomplete
		}
		j, e = s.reopenOptionalDay(day)
		if e != nil {
			return e
		}
	}
	if j == nil {
		if len(s.journals) >= MaxOptionalDays {
			return errors.New("optional day capacity exceeded")
		}
		j, e = OpenJournal(filepath.Join(s.root, fmt.Sprint(day)), s.owner, day, 10, s.key, s.validate)
		if e != nil {
			return e
		}
		s.journals[day] = j
		j.create = s.createOptionalControl
		j.optionalHold = s.holdLive
	}
	if j.log == nil {
		if e := s.optionalRetainedCapacity(j, reservation); e != nil {
			return e
		}
		if e := capacity(reservation); e != nil {
			return e
		}
		if len(records) != 1 {
			return store.ErrCorrupt
		}
		kind := record.Kind
		if kind == "access" {
			kind = "receipt"
		}
		_, result := j.Append(record.ID, kind, record.Finished, func(src Source) ([]byte, error) {
			return json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), record})
		})
		if result.Status != store.Durable {
			if result.Err != nil {
				return result.Err
			}
			return store.ErrCorrupt
		}
		return nil
	}
	result := j.appendOptionalBatch(records, func(size, retained int64) error {
		if e := s.optionalRetainedCapacity(j, retained); e != nil {
			return e
		}
		return capacity(size)
	})
	if result.Status != store.Durable {
		if result.Err != nil {
			return result.Err
		}
		return store.ErrCorrupt
	}
	return nil
}

// Sweep は全満了bytesを128行の署名frameへ分割して回収する。公開pack整理の有無には依存しない。
func (s *OptionalStore) Sweep(now time.Time) (int, error) {
	return s.SweepReserved(now, func(int64) (func(), error) { return func() {}, nil })
}

// SweepReserved は日別の必要作業量を共通予約し、全日満了は小さなcheckpointだけで回収する。
// reserveはStoreのmutexを取得せず、成功時に一度だけ呼べる解放関数を返す。
func (s *OptionalStore) SweepReserved(now time.Time, reserve func(int64) (func(), error)) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepReserved(now, reserve)
}

// SweepReservedChecked は同じ元所有排他内で予約再読取り/案件照合を先行し、許可時だけ回収を進める。
// checkはmetadataだけを受け取り、元Storeの公開methodや案件mutexを取得しない。nilは拒否する。
func (s *OptionalStore) SweepReservedChecked(now time.Time, reserve func(int64) (func(), error), check func(OptionalHoldReferences) error) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || check == nil || s.holdsStopped && s.retirementStopped {
		s.cleanupFailed = true
		return 0, store.ErrIncomplete
	}
	s.holdProtections = nil
	if e := s.loadOptionalHolds(false); e != nil {
		s.holdsStopped = true
		s.cleanupFailed = true
		return 0, e
	}
	s.holdsStopped = false
	if e := check(optionalHoldReferences{s}); e != nil {
		s.cleanupFailed = true
		return 0, e
	}
	return s.sweepReserved(now, reserve)
}

// sweepReserved は元所有排他下で必要な日別予約と回収を実行する。
func (s *OptionalStore) sweepReserved(now time.Time, reserve func(int64) (func(), error)) (int, error) {
	fail := func(n int, e error) (int, error) { s.cleanupFailed = true; return n, e }
	if s.holdsStopped {
		return fail(0, store.ErrIncomplete)
	}
	if s.closed || reserve == nil {
		return fail(0, errors.New("optional store closed or reservation missing"))
	}
	at := domain.Time(now.UnixNano())
	if at < s.floor {
		return fail(0, store.ErrCorrupt)
	}
	days := make([]uint64, 0, len(s.journals))
	for day := range s.journals {
		days = append(days, day)
	}
	sort.Slice(days, func(i, j int) bool { return days[i] < days[j] })
	removed := 0
	for _, day := range days {
		_, budget, e := optionalReclaimPlan(s.journals[day], at)
		if e != nil {
			return fail(removed, e)
		}
		if budget == 0 {
			continue
		}
		release, e := reserve(budget)
		if e != nil {
			return fail(removed, e)
		}
		if release == nil {
			return fail(removed, store.ErrCorrupt)
		}
		n, e := func() (int, error) {
			defer release()
			j := s.journals[day]
			if j.stopped {
				checkpoint := filepath.Join(s.root, fmt.Sprintf("%d.checkpoint.json", day))
				if _, err := os.Lstat(checkpoint); os.IsNotExist(err) {
					var e error
					j, e = s.reopenOptionalDay(day)
					if e != nil {
						return 0, e
					}
				} else if err != nil {
					return 0, err
				}
			}
			expired, _, e := optionalReclaimPlan(j, at)
			if e != nil {
				return 0, e
			}
			if e = s.retireOptionalDay(day, at); e != nil {
				return 0, e
			}
			if s.journals[day] == nil {
				s.floor = max(s.floor, at)
				return expired, nil
			}
			n, e := j.PruneOptionalAll(at, nil)
			if n > 0 {
				s.floor = max(s.floor, at)
			}
			if e != nil {
				return n, e
			}
			if e = s.retireOptionalDay(day, at); e != nil {
				return n, e
			}
			return n, nil
		}()
		removed += n
		if e != nil {
			return fail(removed, e)
		}
	}
	if e := s.expireOptionalCheckpoints(at); e != nil {
		return fail(removed, e)
	}
	s.cleanupFailed = false
	return removed, nil
}

// optionalReclaimPlan は本人情報を外へ出さず、満了件数と必要な一時保存上限だけを求める。
func optionalReclaimPlan(j *Journal, now domain.Time) (int, int64, error) {
	expired, live := 0, 0
	for _, row := range j.entries {
		if row.Event.Kind == "tombstone" {
			continue
		}
		var p OptionalPayload
		if !optionalKind(row.Event.Kind) || json.Unmarshal(row.Payload, &p) != nil {
			return 0, 0, store.ErrCorrupt
		}
		if p.Record.Until <= now && !j.optionalHeld(p.Record.ID, now) {
			expired++
		} else {
			live++
		}
	}
	// 保存不明の列は、再読込みで判明する現在状態snapshot分まで予約する。
	if j.stopped {
		return expired, MaxOptionalDayBytes + (256 << 10), nil
	}
	if len(j.entries) > 0 && live == 0 {
		return expired, 128 << 10, nil
	}
	if expired > 0 {
		return expired, MaxOptionalDayBytes + (256 << 10), nil
	}
	return 0, 0, nil
}

// CleanupFailed は前回巡回の失敗状態だけを返す。
func (s *OptionalStore) CleanupFailed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleanupFailed
}

// Close は日別正本を閉じ、保持した秘密鍵コピーを消去する。
func (s *OptionalStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var errs []error
	for _, j := range s.journals {
		errs = append(errs, j.Close())
	}
	clear(s.key)
	return errors.Join(errs...)
}

// optionalDirectoryCapacity は未知entry・symlinkを拒否し、128MiBの保存上限を先に検査する。
func optionalDirectoryCapacity(root string, requested int64) error {
	return optionalDirectoryCapacityLimit(root, requested, MaxOptionalStoreBytes)
}

func optionalDirectoryCapacityLimit(root string, requested, limit int64) error {
	var total int64
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if entry.IsDir() {
			if info.Mode().Perm() != 0700 {
				return store.ErrCorrupt
			}
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return store.ErrCorrupt
		}
		total += info.Size()
		if total > limit-requested {
			return errors.New("optional storage capacity exceeded")
		}
		return nil
	})
}

// StartupDiscarded は正本作成前の不完全候補を起動時に回収した件数を返す。
func (s *OptionalStore) StartupDiscarded() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startupDiscarded
}

// optionalRetainedCapacity は圧縮率と独立して、現在行の展開量・snapshot生成量を有界にする。
// Store排他内で使い、圧縮で物理上限に余裕があっても展開上限を広げない。
func (s *OptionalStore) optionalRetainedCapacity(day *Journal, added int64) error {
	if added < 0 || added > MaxOptionalDayBytes || day.retainedBytes > MaxOptionalDayBytes-added {
		return errors.New("optional expanded day capacity exceeded")
	}
	total := added
	for _, journal := range s.journals {
		if journal.retainedBytes > MaxOptionalStoreBytes-total {
			return errors.New("optional expanded store capacity exceeded")
		}
		total += journal.retainedBytes
	}
	return nil
}
