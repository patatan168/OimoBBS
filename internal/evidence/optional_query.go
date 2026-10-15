// 案件に対応する非必須HTTP原本を所有列内で有界取得し、通常期限を延長しない。
package evidence

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

const MaxOptionalQueryRecords = 100
const MaxOptionalQueryBytes = 8 << 20

var ErrOptionalQueryLimit = errors.New("optional HTTP query capacity exceeded")
var ErrOptionalQueryScope = errors.New("invalid optional HTTP query scope")

// OptionalQueryScope は一板・明示期間・保全済み受理操作の交差範囲。全サイト走査結果は返さない。
type OptionalQueryScope struct {
	Board      domain.ID
	From, To   domain.Time
	Operations []domain.ID
	Records    []domain.ID // 固定intent再開時のHTTP原本ID。空なら追加制限なし。
}

// OptionalEvidence は検証済み原本の独立コピー。公開系や一般監査へ渡してはならない。
type OptionalEvidence struct {
	SourceOwner domain.ID      `json:"source_owner_id"`
	SourceDay   domain.U64     `json:"source_subkey"`
	SourceSeq   domain.U64     `json:"source_control_seq"`
	SourceSHA   domain.Hash    `json:"source_event_sha256"`
	Record      OptionalRecord `json:"record"`
}

// Query は保存/回収と同じmutexで署名検証済み行を取得する。超過時は部分結果を返さない。
// nowは期限判定用。実時計より古い時刻による期限延長を許さず、停止中列を復旧しない。
func (s *OptionalStore) Query(ctx context.Context, scope OptionalQueryScope, now time.Time) ([]OptionalEvidence, error) {
	entries, e := s.queryEntries(ctx, scope, now, false, false)
	if e != nil {
		return nil, e
	}
	rows := make([]OptionalEvidence, 0, len(entries))
	for _, entry := range entries {
		var p OptionalPayload
		if strictjson.Decode(entry.Payload, &p) != nil {
			return nil, store.ErrCorrupt
		}
		rows = append(rows, OptionalEvidence{p.Owner, p.Day, p.Seq, entry.Event.EventSHA, p.Record})
	}
	return rows, nil
}

// QuerySigned は案件コピー用の署名付き原本を取得する。公開/管理HTTPへ生のEntryを返してはならない。
// 同一の板・操作・期間・期限条件とmutexを使用し、署名envelopeを含め100件/8MiBまでに制限する。
// 戻り値は正本から独立する。取得だけでは保全も原本期限の延長も行わない。
func (s *OptionalStore) QuerySigned(ctx context.Context, scope OptionalQueryScope, now time.Time) ([]Entry, error) {
	return s.queryEntries(ctx, scope, now, true, false)
}

// queryEntries は署名付き/部分列の双方の取得条件を共有し、回収との隙間を作らない。
func (s *OptionalStore) queryEntries(ctx context.Context, scope OptionalQueryScope, now time.Time, signed, unbound bool) ([]Entry, error) {
	if scope.Board == (domain.ID{}) || scope.From <= 0 || scope.From >= scope.To || !unbound && len(scope.Operations) == 0 || unbound && len(scope.Operations) != 0 || len(scope.Operations) > 100 {
		return nil, ErrOptionalQueryScope
	}
	ops := make(map[domain.ID]bool, len(scope.Operations))
	for _, id := range scope.Operations {
		if id == (domain.ID{}) || ops[id] {
			return nil, ErrOptionalQueryScope
		}
		ops[id] = true
	}
	if len(scope.Records) > MaxOptionalQueryRecords {
		return nil, ErrOptionalQueryScope
	}
	ids := map[domain.ID]bool{}
	for _, id := range scope.Records {
		if id == (domain.ID{}) || ids[id] {
			return nil, ErrOptionalQueryScope
		}
		ids[id] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, store.ErrIncomplete
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	at := max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano()))
	if at < s.floor {
		return nil, store.ErrCorrupt
	}
	days := make([]uint64, 0, len(s.journals))
	for day := range s.journals {
		days = append(days, day)
	}
	sort.Slice(days, func(i, j int) bool { return days[i] < days[j] })
	rows := []Entry{}
	bytes := 0
	for _, day := range days {
		j := s.journals[day]
		if j.stopped {
			return nil, store.ErrIncomplete
		}
		e := j.Visit(func(entry Entry) error {
			if e := ctx.Err(); e != nil {
				return e
			}
			if !optionalKind(entry.Event.Kind) {
				return nil
			}
			var p OptionalPayload
			if strictjson.Decode(entry.Payload, &p) != nil {
				return store.ErrCorrupt
			}
			r := p.Record
			if len(ids) > 0 && !ids[r.ID] {
				return nil
			}
			if !optionalQueryMatches(r, scope, ops, unbound, at) {
				return nil
			}
			size := len(entry.Payload)
			if signed {
				if _, e := VerifyOptionalEntry(entry, s.site, s.key.Public().(ed25519.PublicKey)); e != nil {
					return e
				}
				raw, e := json.Marshal(entry)
				if e != nil {
					return e
				}
				size = len(raw)
			}
			if len(rows) >= MaxOptionalQueryRecords || size > MaxOptionalQueryBytes-bytes {
				return ErrOptionalQueryLimit
			}
			// 元bytesとenvelopeを別々に所有し、呼出元の変更で正本を壊さない。
			rows = append(rows, Entry{Event: entry.Event, Payload: slices.Clone(entry.Payload)})
			bytes += size
			return nil
		})
		if e != nil {
			return nil, e
		}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	// 走査中の期限到達は結果から除き、照会によって延長しない。
	cutoff := max(at, domain.Time(time.Now().UnixNano()))
	live := rows[:0]
	for _, row := range rows {
		var p OptionalPayload
		if strictjson.Decode(row.Payload, &p) != nil {
			return nil, store.ErrCorrupt
		}
		if p.Record.Until > cutoff {
			live = append(live, row)
		}
	}
	return live, nil
}
