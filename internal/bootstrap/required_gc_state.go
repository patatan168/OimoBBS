// 必須原本の自動回収設定と本文なし走査位置をsite制御列へ耐久保存する。
package bootstrap

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"strconv"
	"time"
)

const requiredGCStateSchema = "required-original-gc-v1"

type requiredGCState struct {
	Schema  string      `json:"schema"`
	Site    domain.ID   `json:"site_id"`
	Enabled bool        `json:"enabled"`
	Round   domain.U64  `json:"round"`
	Board   *domain.ID  `json:"board_id"`
	Key     domain.U64  `json:"thread_key"`
	After   domain.U64  `json:"after_sequence"`
	Day     domain.U64  `json:"after_source_subkey"`
	Proof   domain.Hash `json:"public_reclamation_sha256"`
	Advance bool        `json:"advance_thread"`
	At      domain.Time `json:"updated_at_ns"`
}

func decodeRequiredGCState(key string, raw json.RawMessage) (requiredGCState, error) {
	var v requiredGCState
	if key != "originals" || strictjson.Decode(raw, &v) != nil || !validRequiredGCState(v) {
		return v, store.ErrCorrupt
	}
	return v, nil
}

func validRequiredGCState(v requiredGCState) bool {
	if v.Schema != requiredGCStateSchema || v.Site == (domain.ID{}) || v.Round == 0 || v.At <= 0 {
		return false
	}
	if v.Board == nil {
		return emptyRequiredGCCursor(v)
	}
	return validRequiredGCOwnedCursor(v)
}

func (v requiredGCState) boardID() domain.ID {
	if v.Board == nil {
		return domain.ID{}
	}
	return *v.Board
}

func validRequiredGCOwnedCursor(v requiredGCState) bool {
	if v.Key == 0 || v.boardID() == (domain.ID{}) || v.After > store.MaxPackEntries || !validRequiredGCDay(v.Day) {
		return false
	}
	if v.Proof == (domain.Hash{}) {
		return v.After == 0 && v.Day == 0
	}
	return true
}

func emptyRequiredGCCursor(v requiredGCState) bool {
	return v.Key == 0 && v.After == 0 && v.Day == 0 && v.Proof == (domain.Hash{}) && !v.Advance
}

func validRequiredGCDay(day domain.U64) bool {
	if day == 0 {
		return true
	}
	raw := strconv.FormatUint(uint64(day), 10)
	_, e := time.Parse("20060102", raw)
	return len(raw) == 8 && e == nil
}

func validateRequiredGCState(key string, old, next json.RawMessage) error {
	v, e := decodeRequiredGCState(key, next)
	if e != nil {
		return e
	}
	if len(old) == 0 {
		if v.Board != nil || v.Round != 1 {
			return store.ErrCorrupt
		}
		return nil
	}
	p, e := decodeRequiredGCState(key, old)
	if e != nil || v.Site != p.Site || v.At < p.At {
		return store.ErrCorrupt
	}
	return validateRequiredGCCursor(p, v)
}

// validateRequiredGCCursor は同じ走査窓の逆行、scope差替えと未完了周回の巻戻しを拒否する。
func validateRequiredGCCursor(p, v requiredGCState) error {
	if v.Round == p.Round && v.boardID() == p.boardID() && v.Key == p.Key {
		return validateRequiredGCSameScope(p, v)
	}
	if p.Board != nil && !p.Advance {
		return store.ErrCorrupt
	}
	if v.After != 0 || v.Day != 0 || v.Advance || v.Proof != (domain.Hash{}) {
		return store.ErrCorrupt
	}
	return validateRequiredGCNextScope(p, v)
}

func validateRequiredGCSameScope(p, v requiredGCState) error {
	if p.Proof != (domain.Hash{}) && v.Proof != p.Proof || v.After < p.After {
		return store.ErrCorrupt
	}
	if v.After == p.After && v.Day < p.Day || v.After > p.After && v.Day != 0 {
		return store.ErrCorrupt
	}
	if p.Advance && !v.Advance {
		return store.ErrCorrupt
	}
	return nil
}

func validateRequiredGCNextScope(p, v requiredGCState) error {
	if v.Round == p.Round {
		nextBoard, previousBoard := v.boardID(), p.boardID()
		order := bytes.Compare(nextBoard[:], previousBoard[:])
		if order > 0 || order == 0 && v.Key > p.Key {
			return nil
		}
	}
	if p.Round != ^domain.U64(0) && v.Round == p.Round+1 && p.Advance {
		return nil
	}
	return store.ErrCorrupt
}

// readRequiredGCState は現在site/有効板/reader/時計へ設定を束縛する。行不在は未有効化。
func readRequiredGCState(state store.ControlState, site siteState, now domain.Time) (*requiredGCState, error) {
	row, ok := state.Rows["required_gc:originals"]
	if !ok {
		return nil, nil
	}
	v, e := decodeRequiredGCState("originals", row.Value)
	if e != nil || !requiredGCMatchesSite(row, v, site, now) {
		return nil, store.ErrCorrupt
	}
	if v.Board != nil {
		dirs, e := siteDirectories(state)
		id := v.boardID()
		if e != nil || dirs[id] == nil || dirs[id].Status != "active" {
			return nil, store.ErrCorrupt
		}
	}
	return &v, nil
}

func requiredGCMatchesSite(row store.ControlRow, v requiredGCState, site siteState, now domain.Time) bool {
	return row.Expires == nil && v.Site == site.ID && site.MinimumReader >= 48 && v.At <= now
}
