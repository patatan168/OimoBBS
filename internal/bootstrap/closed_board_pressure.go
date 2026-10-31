// 閉鎖板の既回収スレッドにも、既存の署名と保全検査を保って原本早期回収を接続する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

func validateClosedBoardPressure(old, next json.RawMessage) error {
	var v app.ClosedBoardPressure
	if len(old) != 0 || strictjson.Decode(next, &v) != nil || v.Proof == (domain.Hash{}) || v.ClosedAt <= 0 || v.At < v.ClosedAt || v.Signature == "" {
		return store.ErrCorrupt
	}
	return nil
}

// authorizeClosedPressureOwned は案件保全と容量不足または閉鎖最終期限を検査した後にだけ呼ぶ。
func (b *postingBoard) authorizeClosedPressureOwned(key uint64, now domain.Time) error {
	public := b.key.Public().(ed25519.PublicKey)
	log := b.deletions[key]
	if log == nil {
		return store.ErrIncomplete
	}
	proof, err := readBodyReclamation(log.State(), b.owner, key, public)
	if err != nil || proof == nil {
		return store.ErrIncomplete
	}
	if proof.Kind == "pressure" || proof.Kind == "closure" {
		return nil
	}
	if proof.ClosedPressure == nil {
		permission, err := app.SignClosedBoardPressure(*proof, domain.Time(b.closedAt.Load()), now, b.key)
		if err != nil {
			return err
		}
		if err = appendControl(log, "closed_board_pressure", []store.Mutation{mutation("reclamation", "closed_pressure", permission, nil)}, []string{b.owner.String()}); err != nil {
			b.stopped = true
			return err
		}
		proof.ClosedPressure = &permission
		if err = b.afterDeletion("closed_pressure:durable"); err != nil {
			b.stopped = true
			return err
		}
	}
	return b.threads[key].UseClosedBoardPressure(*proof.ClosedPressure, now, public)
}
