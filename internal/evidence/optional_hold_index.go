// 元予約の登録済み案件集合を署名固定し、新所有者でも一部の予約file欠落を検出する。
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// OptionalHoldIndexFile は有効化済み元予約領域で必須の署名集合索引名。
const OptionalHoldIndexFile = "index.json"
const optionalHoldIndexFile = OptionalHoldIndexFile

type optionalHoldIndexPayload struct {
	Owner    domain.ID   `json:"source_owner_id"`
	Subkey   domain.U64  `json:"source_subkey"`
	Schema   string      `json:"schema"`
	Site     domain.ID   `json:"site_id"`
	Sequence domain.U64  `json:"source_control_seq"`
	At       domain.Time `json:"recorded_at_ns"`
	Cases    []domain.ID `json:"case_ids"`
}
type optionalHoldIndexSaved struct {
	payload    optionalHoldIndexPayload
	event      Event
	retirement *optionalHoldIndexRetirement
}

// optionalHoldIndexOwner は日別原本と個別予約から独立した署名所有者を固定導出する。
func optionalHoldIndexOwner(site domain.ID) domain.ID {
	h := sha256.Sum256(append([]byte("oimo/optional-http-hold-index-owner/v1"), site[:]...))
	var id domain.ID
	copy(id[:], h[:16])
	if id == (domain.ID{}) {
		id[15] = 1
	}
	return id
}

func (s *OptionalStore) decodeOptionalHoldIndex(raw []byte) (optionalHoldIndexSaved, error) {
	return decodeOptionalHoldIndexSigned(raw, s.site, s.key.Public().(ed25519.PublicKey))
}

// validateOptionalHoldIndexNext は集合の脱落・巻戻しと、直後でない署名候補を拒否する。
func validateOptionalHoldIndexNext(old, next optionalHoldIndexSaved) error {
	if old.payload.Sequence == 0 {
		if next.payload.Sequence != 1 || next.event.PreviousSHA != (domain.Hash{}) || len(next.payload.Cases) != 0 {
			return store.ErrCorrupt
		}
		return nil
	}
	if next.payload.Sequence == old.payload.Sequence {
		if !equalOptionalHoldBytes(old.event, next.event) {
			return store.ErrCorrupt
		}
		return nil
	}
	if next.payload.Sequence <= old.payload.Sequence || next.payload.Sequence-old.payload.Sequence != 1 || next.event.PreviousSHA != old.event.EventSHA || next.payload.At < old.payload.At {
		return store.ErrCorrupt
	}
	return validateOptionalHoldIndexMembership(old, next)
}

// loadOptionalHoldIndex は読取り検査で候補を保持し、起動時だけ既知の直後候補を補完する。
func (s *OptionalStore) loadOptionalHoldIndex(readOnly bool) (optionalHoldIndexSaved, error) {
	path := filepath.Join(s.root, optionalHoldsDir, optionalHoldIndexFile)
	var old optionalHoldIndexSaved
	raw, e := readOptionalPrivate(path, optionalHoldFileLimit)
	if e == nil {
		old, e = s.decodeOptionalHoldIndex(raw)
	}
	if e != nil && !os.IsNotExist(e) {
		return old, e
	}
	if s.holdIndex.payload.Sequence != 0 {
		if old.payload.Sequence == 0 {
			return old, store.ErrCorrupt
		}
		if e := validateOptionalHoldIndexNext(s.holdIndex, old); e != nil {
			return old, e
		}
	}
	raw, e = readOptionalPrivate(path+".pending", optionalHoldFileLimit)
	if os.IsNotExist(e) {
		return old, nil
	}
	if e != nil {
		return old, e
	}
	next, e := s.decodeOptionalHoldIndex(raw)
	if e != nil {
		return old, e
	}
	if e = validateOptionalHoldIndexNext(old, next); e != nil {
		return old, e
	}
	if readOnly {
		return old, store.ErrIncomplete
	}
	// 回収候補は現在サイトの認可を伴う専用再開まで設置しない。
	if next.retirement != nil {
		return old, store.ErrIncomplete
	}
	if next.payload.Sequence == old.payload.Sequence {
		e = os.Remove(path + ".pending")
	} else {
		e = os.Rename(path+".pending", path)
	}
	if e != nil {
		return old, e
	}
	if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
		return old, e
	}
	return next, nil
}

// saveOptionalHoldIndex は候補を同期してから登録集合を確定し、保存不明ならGCを停止する。
func (s *OptionalStore) saveOptionalHoldIndex(p optionalHoldIndexPayload) error {
	return s.saveOptionalHoldIndexRetirement(p, nil)
}

// saveOptionalHoldIndexRetirement は専用認可済みの除去候補も既存の同期手順で確定する。
func (s *OptionalStore) saveOptionalHoldIndexRetirement(p optionalHoldIndexPayload, retirement *optionalHoldIndexRetirement) error {
	if e := optionalDirectoryCapacity(s.root, 2*optionalHoldFileLimit); e != nil {
		return e
	}
	p.Owner = optionalHoldIndexOwner(s.site)
	body, e := marshalOptionalHoldIndexPayload(p, retirement)
	if e != nil {
		return e
	}
	event, e := Seal(Source{optionalHoldIndexOwner(s.site), 0, uint64(p.Sequence)}, s.site, "checkpoint", body, s.holdIndex.event.EventSHA, 10, s.key)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(event)
	if e != nil {
		return e
	}
	if len(raw) > optionalHoldFileLimit {
		return ErrOptionalQueryLimit
	}
	path := filepath.Join(s.root, optionalHoldsDir, optionalHoldIndexFile)
	if e := s.syncOptionalHoldIndexCandidate(path, raw); e != nil {
		return e
	}
	if e := s.installOptionalHoldIndexCandidate(path); e != nil {
		return e
	}
	s.holdIndex = optionalHoldIndexSaved{payload: p, event: event, retirement: retirement}
	return nil
}

// syncOptionalHoldIndexCandidate は排他的候補作成からSync/Closeまでを行い、保存中のGCを停止する。
func (s *OptionalStore) syncOptionalHoldIndexCandidate(path string, raw []byte) error {
	f, e := os.OpenFile(path+".pending", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		s.holdsStopped = true
		return e
	}
	s.holdsStopped = true
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if s.checkpoint != nil {
		if e = s.checkpoint("hold-index:sync"); e != nil {
			return e
		}
	}
	return nil
}

// installOptionalHoldIndexCandidate は同期済み候補のrenameと親Syncを完了し、失敗時は候補を保持する。
func (s *OptionalStore) installOptionalHoldIndexCandidate(path string) error {
	if e := os.Rename(path+".pending", path); e != nil {
		return e
	}
	if s.checkpoint != nil {
		if e := s.checkpoint("hold-index:rename"); e != nil {
			return e
		}
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// registerOptionalHoldCase は個別予約の候補Sync後、正本renameより先に案件集合を確定する。
func (s *OptionalStore) registerOptionalHoldCase(id domain.ID) error {
	if slices.Contains(s.holdIndex.payload.Cases, id) {
		return nil
	}
	if s.holdIndex.payload.Sequence == 0 {
		return store.ErrIncomplete
	}
	p := s.holdIndex.payload
	if len(p.Cases) >= MaxOptionalHolds {
		return ErrOptionalQueryLimit
	}
	p.Cases = append(slices.Clone(p.Cases), id)
	slices.SortFunc(p.Cases, func(a, b domain.ID) int {
		if a.String() < b.String() {
			return -1
		}
		if a == b {
			return 0
		}
		return 1
	})
	p.Sequence++
	p.At = max(p.At, domain.Time(time.Now().UnixNano()))
	return s.saveOptionalHoldIndex(p)
}

// InitializeOptionalHolds は先行site作成intentの後で呼び、空の登録集合も署名Syncする。
// active siteからの起動では先にInspectOptionalHoldSetで存在を確認し、欠落を再作成しない。
func (s *OptionalStore) InitializeOptionalHolds() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.holdsStopped {
		return store.ErrIncomplete
	}
	return s.initializeOptionalHolds()
}

// initializeOptionalHolds は元所有mutexの下で専用領域と空の署名索引を確定する。
func (s *OptionalStore) initializeOptionalHolds() error {
	dir := filepath.Join(s.root, optionalHoldsDir)
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	if e := store.SyncDirectory(filepath.Dir(dir)); e != nil {
		return e
	}
	if e := s.loadOptionalHolds(false); e != nil {
		s.holdsStopped = true
		return e
	}
	if s.holdIndex.payload.Sequence != 0 {
		if e := s.validateOptionalHoldSources(max(s.floor, domain.Time(time.Now().UnixNano()))); e != nil {
			s.holdsStopped = true
			return e
		}
		return nil
	}
	p := optionalHoldIndexPayload{Schema: "optional-http-hold-index-v2", Site: s.site, Sequence: 1, At: max(s.floor, domain.Time(time.Now().UnixNano())), Cases: []domain.ID{}}
	if e := s.saveOptionalHoldIndex(p); e != nil {
		return e
	}
	s.holdsStopped = false
	return nil
}

// InspectOptionalHoldSet は有効化済みsiteの起動前に、署名登録集合と全予約fileの存在を検査する。
// 新規作成・候補補完・原本GCを行わず、空でも未初期化の領域を拒否する。
func InspectOptionalHoldSet(root string, site domain.ID, key ed25519.PrivateKey) error {
	if site == (domain.ID{}) || len(key) != ed25519.PrivateKeySize {
		return store.ErrCorrupt
	}
	s := &OptionalStore{root: root, site: site, key: key}
	if e := s.loadOptionalHolds(true); e != nil {
		return e
	}
	if s.holdIndex.payload.Sequence == 0 {
		return store.ErrCorrupt
	}
	return nil
}
