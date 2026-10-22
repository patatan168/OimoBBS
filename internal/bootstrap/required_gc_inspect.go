// 自動回収の保存scope/公開回収digest/走査位置を、私有領域の復旧より前に非変更検査する。
package bootstrap

import (
	"crypto/ed25519"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"time"
)

func inspectRequiredGCJobScope(cfg Config, state store.ControlState, site siteState, boards []persistedBoard, public ed25519.PublicKey) error {
	v, e := readRequiredGCState(state, site, domain.Time(time.Now().UnixNano()))
	if e != nil || v == nil {
		return e
	}
	if v.Board == nil {
		return nil
	}
	for _, b := range boards {
		if b.info.ID == v.boardID() {
			return inspectRequiredGCBoardScope(cfg, b, *v, public)
		}
	}
	return store.ErrCorrupt
}

func inspectRequiredGCBoardScope(cfg Config, b persistedBoard, v requiredGCState, public ed25519.PublicKey) error {
	var water struct {
		Last domain.U64 `json:"last_reserved_key"`
	}
	if strictjson.Decode(b.control.Rows["key_watermark:thread"].Value, &water) != nil || v.Key > water.Last {
		return store.ErrCorrupt
	}
	if v.Proof == (domain.Hash{}) {
		return nil
	}
	id := v.boardID()
	state, e := inspectDeletionControl(filepath.Join(cfg.DataDir, "expiry", id.String(), fmt.Sprint(v.Key)), id, uint64(v.Key))
	if e != nil {
		return e
	}
	proof, e := readBodyReclamation(state, id, uint64(v.Key), public)
	if e != nil || proof == nil {
		return store.ErrCorrupt
	}
	if reclamationDigest(*proof) != v.Proof || v.After > proof.Sequence {
		return store.ErrCorrupt
	}
	if v.Day != 0 {
		return inspectPostingJournalDirectory(filepath.Join(cfg.DataDir, "evidence", id.String(), fmt.Sprint(v.Day)))
	}
	return nil
}
