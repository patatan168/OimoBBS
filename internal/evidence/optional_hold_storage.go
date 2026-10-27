// 元所有列の保全予約を私有fileへ署名保存し、候補Sync/rename途中から既知bytesだけを復旧する。
package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func (s *OptionalStore) decodeOptionalHold(raw []byte, id domain.ID) (optionalHoldSaved, error) {
	var v optionalHoldSaved
	if len(raw) > optionalHoldFileLimit || strictjson.Decode(raw, &v.event) != nil || v.event.RecordID != id || v.event.Kind != "checkpoint" {
		return v, store.ErrCorrupt
	}
	var body []byte
	// seqは署名payload内から取り出し、予約専用ownerへ再び束縛して検証する。
	var p optionalHoldPayload
	decoded, e := base64.StdEncoding.Strict().DecodeString(v.event.Payload)
	if e != nil || strictjson.Decode(decoded, &p) != nil || p.Sequence == 0 {
		return v, store.ErrCorrupt
	}
	body, e = Verify(Source{optionalHoldOwner(s.site), 0, uint64(p.Sequence)}, v.event, v.event.PreviousSHA, 10, s.key.Public().(ed25519.PublicKey))
	if e != nil || strictjson.Decode(body, &p) != nil {
		return v, store.ErrCorrupt
	}
	if p.Schema != "optional-http-hold-v1" || p.Site != s.site || p.Owner != optionalHoldOwner(s.site) || p.Subkey != 0 || p.Binding.Case != id || p.At <= 0 || p.State != "active" && p.State != "released" || len(p.Items) > MaxOptionalQueryRecords {
		return v, store.ErrCorrupt
	}
	// 解除は案件満了後にも記録できる。固定範囲と元期限は変更しない。
	checkAt := p.At
	if p.State == "released" {
		checkAt = min(checkAt, p.Binding.Until-1)
	}
	if !validOptionalHoldBinding(p.Binding, checkAt) {
		return v, store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, item := range p.Items {
		if item.Record == (domain.ID{}) || item.Sequence == 0 || item.SHA == (domain.Hash{}) || item.Expires <= 0 || seen[item.Record] {
			return v, store.ErrCorrupt
		}
		if _, e := time.Parse("20060102", strconv.FormatUint(uint64(item.Day), 10)); e != nil {
			return v, store.ErrCorrupt
		}
		seen[item.Record] = true
	}
	v.payload = p
	return v, nil
}

// validateOptionalHoldNext は候補が同じ確定値か直後の同じ固定集合であることを検査する。
func validateOptionalHoldNext(old optionalHoldSaved, next optionalHoldSaved) error {
	if old.payload.Sequence == 0 {
		if next.payload.Sequence != 1 || next.event.PreviousSHA != (domain.Hash{}) || next.payload.State != "active" {
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
	if next.payload.Sequence <= old.payload.Sequence || next.payload.Sequence-old.payload.Sequence != 1 || next.event.PreviousSHA != old.event.EventSHA || next.payload.At < old.payload.At || !sameOptionalHoldScope(old.payload.Binding, next.payload.Binding) || next.payload.Binding.Revision < old.payload.Binding.Revision || next.payload.Binding.Until < old.payload.Binding.Until || !sameOptionalHoldItems(old.payload.Items, next.payload.Items) || old.payload.State != "active" {
		return store.ErrCorrupt
	}
	return nil
}

func sameOptionalHoldItems(a, b []OptionalHoldSource) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// loadOptionalHolds は未知fileを保持して拒否し、読取り検査では候補を変更しない。
func (s *OptionalStore) loadOptionalHolds(readOnly bool) error {
	dir := filepath.Join(s.root, optionalHoldsDir)
	info, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		if len(s.holds) > 0 || s.holdIndex.payload.Sequence != 0 {
			return store.ErrCorrupt
		}
		s.holds = map[domain.ID]optionalHoldSaved{}
		s.rebuildOptionalHoldIndex()
		return nil
	}
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	files, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	index, e := s.loadOptionalHoldIndex(readOnly)
	if e != nil {
		return e
	}
	if index.retirement != nil && !s.retirementAuthorized {
		return store.ErrIncomplete
	}
	s.holdIndex = index
	s.floor = max(s.floor, index.payload.At)
	if len(files) > 2*MaxOptionalHolds+2 {
		return ErrOptionalQueryLimit
	}
	ids := map[domain.ID]bool{}
	for _, file := range files {
		if file.Name() == optionalHoldIndexFile || file.Name() == optionalHoldIndexFile+".pending" {
			continue
		}
		name := strings.TrimSuffix(file.Name(), ".pending")
		if !strings.HasSuffix(name, ".json") {
			return store.ErrCorrupt
		}
		var id domain.ID
		if json.Unmarshal([]byte(`"`+strings.TrimSuffix(name, ".json")+`"`), &id) != nil || id == (domain.ID{}) || id.String()+".json" != name {
			return store.ErrCorrupt
		}
		ids[id] = true
	}
	if len(ids) > MaxOptionalHolds {
		return ErrOptionalQueryLimit
	}
	if e := s.rejectOptionalRetiredFile(ids); e != nil {
		return e
	}
	for _, id := range index.payload.Cases {
		if !ids[id] {
			return store.ErrCorrupt
		}
	}
	if len(ids) > 0 && index.payload.Sequence == 0 {
		return store.ErrCorrupt
	}
	for id := range s.holds {
		if !ids[id] {
			if e := s.checkKnownOptionalRetiredSource(id); e != nil {
				return e
			}
		}
	}
	loaded := map[domain.ID]optionalHoldSaved{}
	for id := range ids {
		canonical := s.holdFile(id)
		var old optionalHoldSaved
		raw, e := readOptionalPrivate(canonical, optionalHoldFileLimit)
		if e == nil {
			old, e = s.decodeOptionalHold(raw, id)
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		registered := slices.Contains(index.payload.Cases, id)
		if !registered && old.payload.Sequence != 0 {
			return store.ErrCorrupt
		}
		candidate := canonical + ".pending"
		raw, e = readOptionalPrivate(candidate, optionalHoldFileLimit)
		if e == nil {
			next, err := s.decodeOptionalHold(raw, id)
			if err != nil {
				return err
			}
			if err = validateOptionalHoldNext(old, next); err != nil {
				return err
			}
			if readOnly {
				return store.ErrIncomplete
			}
			if !registered {
				if err = s.registerOptionalHoldCase(id); err != nil {
					return err
				}
			}
			if next.payload.Sequence == old.payload.Sequence {
				if err = os.Remove(candidate); err != nil {
					return err
				}
			} else {
				if err = os.Rename(candidate, canonical); err != nil {
					return err
				}
			}
			if err = store.SyncDirectory(filepath.Dir(canonical)); err != nil {
				return err
			}
			old = next
		} else if !os.IsNotExist(e) {
			return e
		}
		if old.payload.Sequence == 0 {
			return store.ErrCorrupt
		}
		if known, found := s.holds[id]; found {
			if e := validateOptionalHoldNext(known, old); e != nil {
				return e
			}
		}
		loaded[id] = old
		s.floor = max(s.floor, old.payload.At)
	}
	s.holds = loaded
	s.rebuildOptionalHoldIndex()
	s.holdsStopped = false
	return nil
}

// saveOptionalHold は候補Sync→rename→親Syncの全成功後だけ排他内の予約を公開する。
func (s *OptionalStore) saveOptionalHold(p optionalHoldPayload, previous domain.Hash) error {
	dir := filepath.Join(s.root, optionalHoldsDir)
	if e := os.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	info, e := os.Lstat(dir)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	if e = store.SyncDirectory(filepath.Dir(dir)); e != nil {
		return e
	}
	if s.holdIndex.payload.Sequence == 0 {
		if e = s.saveOptionalHoldIndex(optionalHoldIndexPayload{Schema: "optional-http-hold-index-v2", Site: s.site, Sequence: 1, At: p.At, Cases: []domain.ID{}}); e != nil {
			return e
		}
	}
	if e = optionalDirectoryCapacity(s.root, 2*optionalHoldFileLimit); e != nil {
		return e
	}
	body, e := json.Marshal(p)
	if e != nil {
		return e
	}
	event, e := Seal(Source{p.Owner, 0, uint64(p.Sequence)}, p.Binding.Case, "checkpoint", body, previous, 10, s.key)
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
	path := s.holdFile(p.Binding.Case)
	candidate := path + ".pending"
	f, e := os.OpenFile(candidate, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
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
		if e = s.checkpoint("hold:sync"); e != nil {
			return e
		}
	}
	if e = s.registerOptionalHoldCase(p.Binding.Case); e != nil {
		return e
	}
	if e = os.Rename(candidate, path); e != nil {
		return e
	}
	if s.checkpoint != nil {
		if e = s.checkpoint("hold:rename"); e != nil {
			return e
		}
	}
	if e = store.SyncDirectory(filepath.Dir(path)); e != nil {
		return e
	}
	if s.holds == nil {
		s.holds = map[domain.ID]optionalHoldSaved{}
	}
	s.holds[p.Binding.Case] = optionalHoldSaved{p, event}
	s.floor = max(s.floor, p.At)
	s.rebuildOptionalHoldIndex()
	s.holdsStopped = false
	return nil
}

// ReloadOptionalHolds は保存不明の予約候補を再検証して復旧する。未知候補を削除しない。
func (s *OptionalStore) ReloadOptionalHolds() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.holdsStopped && s.retirementStopped {
		return store.ErrIncomplete
	}
	if e := s.loadOptionalHolds(false); e != nil {
		s.holdsStopped = true
		return e
	}
	if e := s.validateOptionalHoldSources(max(s.floor, domain.Time(time.Now().UnixNano()))); e != nil {
		s.holdsStopped = true
		return e
	}
	return nil
}
