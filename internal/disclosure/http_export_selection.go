// 提出intentのHTTP固定集合を署名履歴へ照合し、元予約metadataの後処理で生成再開を妨げない。
package disclosure

import (
	"crypto/sha256"
	"encoding/json"

	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// validateHTTPExportSelection は元のhash契約を維持し、予約参照だけの更新は固定集合の変更と区別する。
func (s *Store) validateHTTPExportSelection(c Case, v Export) error {
	if v.HTTPSelection == (domain.Hash{}) {
		return nil
	}
	raw, e := json.Marshal(c.HTTP)
	if e != nil {
		return e
	}
	if sha256.Sum256(raw) == v.HTTPSelection {
		return nil
	}
	original, e := s.httpExportIntent(c.ID, v.ID)
	if e != nil {
		return e
	}
	intent, e := json.Marshal(original)
	if e != nil || sha256.Sum256(intent) != v.HTTPSelection {
		return ErrConflict
	}
	left := *original
	left.Reservation = nil
	left.Released = nil
	if c.HTTP == nil {
		return ErrConflict
	}
	right := *c.HTTP
	right.Reservation = nil
	right.Released = nil
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	if string(a) != string(b) {
		return ErrConflict
	}
	return nil
}

// httpExportIntent は対象生成物が初めて含まれる署名intentのHTTP集合だけを取得する。
// metadata更新時だけ使い、全履歴のCase/payloadを同時に蓄積しない。
func (s *Store) httpExportIntent(id, export domain.ID) (*HTTPHold, error) {
	l := s.logs[id]
	if l == nil {
		return nil, store.ErrCorrupt
	}
	var earliest domain.U64
	var original *HTTPHold
	for _, row := range l.State().Rows {
		a, _, e := s.readAudit(id, row)
		if e != nil {
			return nil, e
		}
		if a.Action != "export_intent" {
			continue
		}
		for _, v := range a.Case.Exports {
			if v.ID != export || earliest != 0 && a.Seq >= earliest {
				continue
			}
			earliest, original = a.Seq, a.Case.HTTP
		}
	}
	if original == nil {
		return nil, ErrConflict
	}
	return original, nil
}
