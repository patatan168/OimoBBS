// 非必須HTTPの元所有列で保全予約を同期し、コピー失敗中の期限回収から原本を保護する。
package evidence

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"math"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

const MaxOptionalHolds = 128

// OptionalHoldsDirectory はreader42以降の元所有列予約領域の固定名。
const OptionalHoldsDirectory = ".holds"
const optionalHoldsDir = OptionalHoldsDirectory
const optionalHoldFileLimit = 64 << 10

// OptionalHoldBinding は先行案件intentと元所有列予約を対応付ける、本人情報のない固定範囲。
type OptionalHoldBinding struct {
	Unbound    bool        `json:"unbound_http"`
	Case       domain.ID   `json:"case_id"`
	Revision   domain.U64  `json:"case_revision"`
	Board      domain.ID   `json:"board_id"`
	From       domain.Time `json:"from_ns"`
	To         domain.Time `json:"to_ns"`
	Operations []domain.ID `json:"operation_ids"`
	Until      domain.Time `json:"hold_until_ns"`
}

// OptionalHoldSource は保護する元sourceだけ。IP・UA・payload・自由文は予約へ含めない。
type OptionalHoldSource struct {
	Record   domain.ID   `json:"record_id"`
	Day      domain.U64  `json:"source_subkey"`
	Sequence domain.U64  `json:"source_control_seq"`
	SHA      domain.Hash `json:"source_event_sha256"`
	Expires  domain.Time `json:"source_expires_at_ns"`
}

// OptionalHoldReceipt は案件列から元予約を照合するための耐久参照。payload/IPを持たない。
type OptionalHoldReceipt struct {
	Site     domain.ID            `json:"site_id"`
	Binding  OptionalHoldBinding  `json:"binding"`
	Sequence domain.U64           `json:"sequence"`
	SHA      domain.Hash          `json:"event_sha256"`
	At       domain.Time          `json:"recorded_at_ns"`
	State    string               `json:"state"`
	Items    []OptionalHoldSource `json:"items"`
}

// OptionalHoldReceipt は耐久確定した予約参照だけを独立コピーで返す。
// 満了後の解除照合にも使うため、期限による開示許可をこの参照だけで判断してはならない。
func (s *OptionalStore) OptionalHoldReceipt(id domain.ID) (OptionalHoldReceipt, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.holdsStopped {
		return OptionalHoldReceipt{}, false, store.ErrIncomplete
	}
	v, found := s.holds[id]
	if !found {
		return OptionalHoldReceipt{}, false, nil
	}
	return s.optionalHoldReceipt(v), true, nil
}

type optionalHoldPayload struct {
	Schema   string               `json:"schema"`
	Owner    domain.ID            `json:"source_owner_id"`
	Subkey   domain.U64           `json:"source_subkey"`
	Sequence domain.U64           `json:"source_control_seq"`
	Site     domain.ID            `json:"site_id"`
	At       domain.Time          `json:"recorded_at_ns"`
	State    string               `json:"state"`
	Binding  OptionalHoldBinding  `json:"binding"`
	Items    []OptionalHoldSource `json:"items"`
}

type optionalHoldSaved struct {
	payload optionalHoldPayload
	event   Event
}

// optionalHoldOwner は日別HTTP原本と異なる署名namespaceを固定導出する。
func optionalHoldOwner(site domain.ID) domain.ID {
	h := sha256.Sum256(append([]byte("oimo/optional-http-hold-owner/v1"), site[:]...))
	var id domain.ID
	copy(id[:], h[:16])
	if id == (domain.ID{}) {
		id[15] = 1
	}
	return id
}

func validOptionalHoldBinding(b OptionalHoldBinding, at domain.Time) bool {
	if b.Case == (domain.ID{}) || b.Revision == 0 || b.Board == (domain.ID{}) || b.From <= 0 || b.From >= b.To || b.To > at || b.Until <= at || at > domain.Time(math.MaxInt64-int64(180*24*time.Hour)) || b.Until > at+domain.Time(180*24*time.Hour) || !validOptionalHoldOperations(b) {
		return false
	}
	seen := map[domain.ID]bool{}
	for _, id := range b.Operations {
		if id == (domain.ID{}) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}

// sameOptionalHoldScope は新しい版・期限以外の固定集合差替えを拒否する。
func sameOptionalHoldScope(a, b OptionalHoldBinding) bool {
	return a.Unbound == b.Unbound && a.Case == b.Case && a.Board == b.Board && a.From == b.From && a.To == b.To && slices.Equal(a.Operations, b.Operations)
}

func (s *OptionalStore) holdLive(id domain.ID, at domain.Time) bool {
	return s.holdsStopped || s.heldUntil[id] > at
}

// rebuildOptionalHoldIndex は複数案件の最も遅い有効期限をIDごとに集約する。
func (s *OptionalStore) rebuildOptionalHoldIndex() {
	s.heldUntil = map[domain.ID]domain.Time{}
	for _, v := range s.holds {
		if v.payload.State == "active" {
			for _, item := range v.payload.Items {
				s.heldUntil[item.Record] = max(s.heldUntil[item.Record], s.optionalHoldUntil(v))
			}
		}
	}
	for _, j := range s.journals {
		j.optionalHold = s.holdLive
	}
}

// optionalHoldEntry は原本がまだ存在することと、元hash/seqを所有mutex内で照合する。
func (s *OptionalStore) optionalHoldEntry(item OptionalHoldSource) (Entry, error) {
	j := s.journals[uint64(item.Day)]
	if j == nil || j.stopped {
		return Entry{}, store.ErrIncomplete
	}
	found, exists, e := j.lookupEntry(item.Record)
	if e != nil {
		return Entry{}, e
	}
	if !exists {
		return Entry{}, store.ErrIncomplete
	}
	r, e := VerifyOptionalEntry(found, s.site, s.key.Public().(ed25519.PublicKey))
	if e != nil || !optionalKind(found.Event.Kind) || r.SourceDay != item.Day || r.SourceSeq != item.Sequence || r.SourceSHA != item.SHA || r.Record.Until != item.Expires {
		return Entry{}, store.ErrCorrupt
	}
	return found, nil
}

// ReserveOptionalHold は先行案件intentの固定原本を元所有mutex内で再照合し、予約をSyncする。
// 呼出元はreader42・現在権限・案件intentと容量枠を確定する。取得だけでは予約にならない。
func (s *OptionalStore) ReserveOptionalHold(ctx context.Context, b OptionalHoldBinding, entries []Entry, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.holdsStopped {
		return store.ErrIncomplete
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	at := max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano()))
	if at < s.floor || !validOptionalHoldBinding(b, at) || len(entries) > MaxOptionalQueryRecords {
		return ErrOptionalQueryScope
	}
	b.Operations = slices.Clone(b.Operations)
	items := make([]OptionalHoldSource, 0, len(entries))
	seen := map[domain.ID]bool{}
	for _, entry := range entries {
		r, e := VerifyOptionalEntry(entry, s.site, s.key.Public().(ed25519.PublicKey))
		if e != nil {
			return e
		}
		v := r.Record
		if seen[v.ID] || !optionalHoldRecordMatches(b, v) {
			return ErrOptionalQueryScope
		}
		seen[v.ID] = true
		items = append(items, OptionalHoldSource{v.ID, r.SourceDay, r.SourceSeq, r.SourceSHA, v.Until})
	}
	unchanged := false
	old, exists := s.holds[b.Case]
	if exists {
		if old.payload.Binding.Until <= at {
			return store.ErrIncomplete
		}
		if old.payload.State != "active" || !sameOptionalHoldScope(old.payload.Binding, b) || !slices.Equal(old.payload.Items, items) || b.Revision < old.payload.Binding.Revision || b.Until < old.payload.Binding.Until {
			return store.ErrCorrupt
		}
		unchanged = b.Revision == old.payload.Binding.Revision && b.Until == old.payload.Binding.Until
	} else if len(s.holds) >= MaxOptionalHolds {
		return ErrOptionalQueryLimit
	}
	for _, item := range items {
		if item.Expires <= at && (!exists || old.payload.Binding.Until <= at) {
			return store.ErrIncomplete
		}
		if _, e := s.optionalHoldEntry(item); e != nil {
			return e
		}
	}
	if unchanged {
		return nil
	}
	p := optionalHoldPayload{Schema: "optional-http-hold-v1", Owner: optionalHoldOwner(s.site), Sequence: 1, Site: s.site, At: at, State: "active", Binding: b, Items: items}
	if exists {
		if old.payload.Sequence == domain.U64(math.MaxUint64) {
			return store.ErrCorrupt
		}
		p.Sequence = old.payload.Sequence + 1
	}
	return s.saveOptionalHold(p, old.event.EventSHA)
}

// ReleaseOptionalHold はコピー確定/案件解除後の元所有列予約を署名して解除する。
// 古い案件版では解除せず、予約期限到達時にもこの台帳の元対象は差し替えない。
func (s *OptionalStore) ReleaseOptionalHold(ctx context.Context, id domain.ID, revision domain.U64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.releaseOptionalHold(ctx, id, revision, now)
}

// ReleaseOptionalHoldChecked は案件へ保存済みのactive参照を同じ所有排他内でCAS照合してから解除する。
// 間に別のactive更新が入った場合はErrIncompleteとし、未保存の参照を飛ばして解除しない。
func (s *OptionalStore) ReleaseOptionalHoldChecked(ctx context.Context, reference OptionalHoldReceipt, revision domain.U64, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, e := s.checkOptionalHoldReceipt(reference)
	if e != nil {
		return e
	}
	if current.State == "active" && (current.Sequence != reference.Sequence || current.SHA != reference.SHA) {
		return store.ErrIncomplete
	}
	return s.releaseOptionalHold(ctx, reference.Binding.Case, revision, now)
}

// releaseOptionalHold は所有排他下で解除正本を同期し、署名候補からの再試行を維持する。
func (s *OptionalStore) releaseOptionalHold(ctx context.Context, id domain.ID, revision domain.U64, now time.Time) error {
	if s.closed || s.holdsStopped {
		return store.ErrIncomplete
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	v, ok := s.holds[id]
	if !ok {
		return store.ErrIncomplete
	}
	at := max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano()))
	if at < s.floor || revision < v.payload.Binding.Revision || v.payload.Sequence == domain.U64(math.MaxUint64) {
		return store.ErrCorrupt
	}
	if v.payload.State == "released" {
		return nil
	}
	p := v.payload
	p.Sequence++
	p.At = at
	p.State = "released"
	p.Binding.Revision = revision
	return s.saveOptionalHold(p, v.event.EventSHA)
}

// QueryOptionalHold は耐久予約の元集合を案件期限内だけ取得する。元7日満了後も予約が必要。
// 管理/公開HTTPへ生Entryを返す経路に登録してはならない。
func (s *OptionalStore) QueryOptionalHold(ctx context.Context, id domain.ID, now time.Time) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.holdsStopped {
		return nil, store.ErrIncomplete
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	at := max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano()))
	v, ok := s.holds[id]
	if at < s.floor || !ok || v.payload.State != "active" || v.payload.Binding.Until <= at {
		return nil, store.ErrIncomplete
	}
	rows := make([]Entry, 0, len(v.payload.Items))
	total := 0
	for _, item := range v.payload.Items {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		entry, e := s.optionalHoldEntry(item)
		if e != nil {
			return nil, e
		}
		raw, e := json.Marshal(entry)
		if e != nil {
			return nil, e
		}
		total += len(raw)
		if total > MaxOptionalQueryBytes {
			return nil, ErrOptionalQueryLimit
		}
		rows = append(rows, entry)
	}
	if v.payload.Binding.Until <= domain.Time(time.Now().UnixNano()) {
		return nil, store.ErrIncomplete
	}
	return rows, nil
}

// validateOptionalHoldSources は有効予約の原本欠落を、起動時に空の履歴として扱わない。
func (s *OptionalStore) validateOptionalHoldSources(at domain.Time) error {
	verified := map[OptionalHoldSource]bool{}
	for _, v := range s.holds {
		if v.payload.State == "active" && s.optionalHoldUntil(v) > at {
			for _, item := range v.payload.Items {
				if verified[item] {
					continue
				}
				if _, e := s.optionalHoldEntry(item); e != nil {
					return e
				}
				verified[item] = true
			}
		}
	}
	return nil
}

func (s *OptionalStore) holdFile(id domain.ID) string {
	return filepath.Join(s.root, optionalHoldsDir, id.String()+".json")
}

// equalOptionalHoldBytes は同じseqの候補をbyte単位でしか受け入れない。
func equalOptionalHoldBytes(a, b Event) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
}

// holdsProtectDay は終端checkpointの復旧前にも予約済み原本日の削除を拒否する。
func (s *OptionalStore) holdsProtectDay(day uint64, at domain.Time) bool {
	for _, v := range s.holds {
		if v.payload.State == "active" && s.optionalHoldUntil(v) > at {
			for _, item := range v.payload.Items {
				if uint64(item.Day) == day {
					return true
				}
			}
		}
	}
	return false
}
