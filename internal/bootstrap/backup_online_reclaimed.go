// 回収済み原本を含むオンラインcopyは、元署名とcarry正本を使う既存復旧経路で照合する。
package bootstrap

import (
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

// openOnlineReclaimedPosting はcopy側の板正本へcarryを束縛し、原本回収の有無で既存Openを選ぶ。
func openOnlineReclaimedPosting(root string, b *postingBoard, control *store.ControlLog, key uint64, journals []*evidence.Journal, state store.ControlState, proof *app.BodyReclamation) (*app.PostingLog, error) {
	parent := filepath.Join(root, "thread", b.owner.String())
	now := domain.Time(time.Now().UnixNano())
	public := b.key.Public().(ed25519.PublicKey)
	if proof == nil {
		return app.OpenPosting(parent, b.owner, key, journals, journals[0], now)
	}
	view := &postingBoard{owner: b.owner, control: control, key: b.key, clock: time.Now}
	carry, e := view.boundBodyCarry(state, *proof)
	if e != nil {
		return nil, e
	}
	if carry == nil {
		return nil, store.ErrCorrupt
	}
	retired, e := hasOnlineRetiredPosting(journals, key)
	if e != nil {
		return nil, e
	}
	if retired {
		return app.OpenPostingWithRetiredOriginals(parent, b.owner, key, journals, journals[0], now, *proof, carry, public)
	}
	p, e := app.OpenPostingWithReclamation(parent, b.owner, key, journals, journals[0], now, proof, public)
	if e != nil {
		return nil, e
	}
	if e = p.RestoreBodyCarry(*carry, now, public); e != nil {
		return nil, errors.Join(e, p.Close())
	}
	return p, nil
}

// hasOnlineRetiredPosting は検証済みjournalの回収証跡に指定キーが含まれるか確認する。
func hasOnlineRetiredPosting(journals []*evidence.Journal, key uint64) (bool, error) {
	for _, j := range journals {
		rows, e := j.RequiredRetirements()
		if e != nil {
			return false, e
		}
		for _, row := range rows {
			if row.Identity.ThreadKey == domain.U64(key) {
				return true, nil
			}
		}
	}
	return false, nil
}
