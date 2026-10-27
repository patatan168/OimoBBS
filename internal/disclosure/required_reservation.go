// 必須原本の耐久予約参照を先行案件intentへ束縛し、予約確認付きcopyを再開する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"slices"
	"time"
)

// RequiredSourceHold は本文なしの元予約/解除参照。未保全は明示nullで保存する。
type RequiredSourceHold struct {
	Reservation app.RequiredHoldReceipt  `json:"source_reservation"`
	Released    *app.RequiredHoldReceipt `json:"source_release"`
}

// RequiredReservationBinding は最初の固定対象intentの版と現在期限を元所有列向けに返す。
func (s *Store) RequiredReservationBinding(c Case, now time.Time) (app.RequiredHoldBinding, error) {
	current, e := s.AuthorizeState(c.ID, c.ETag(), now)
	if e != nil {
		return app.RequiredHoldBinding{}, e
	}
	if current.State != "preparing" && current.State != "partial" {
		return app.RequiredHoldBinding{}, ErrConflict
	}
	if current.Required != nil {
		return current.Required.Reservation.Binding, nil
	}
	var revision domain.U64
	e = s.walkHistory(c.ID, s.logs[c.ID].State(), func(a Audit, _ evidence.Event) error {
		if revision == 0 && a.Action == "hold_intent" && len(a.Case.Items) != 0 {
			revision = a.Seq
		}
		return nil
	})
	if e != nil {
		return app.RequiredHoldBinding{}, e
	}
	if revision == 0 {
		return app.RequiredHoldBinding{}, store.ErrCorrupt
	}
	return app.RequiredHoldBinding{Case: current.ID, Revision: revision, Board: current.Scope.Board, Thread: current.Scope.Thread, From: current.Scope.From, To: current.Scope.To, Until: current.Until}, nil
}

// BindRequiredReservation は元予約Sync後、copy前に信頼済み元参照を案件へ署名する。
// 呼出元は現在元署名/認可/reader46を先に照合する。
func (s *Store) BindRequiredReservation(id, actor domain.ID, etag string, receipt app.RequiredHoldReceipt, now time.Time) (Case, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	binding, e := s.RequiredReservationBinding(c, now)
	if e != nil {
		return c, e
	}
	if receipt.Binding != binding || receipt.State != "active" || receipt.Binding.Until <= domain.Time(now.UnixNano()) {
		return c, store.ErrCorrupt
	}
	if c.Required != nil {
		if !sameRequiredReceipt(c.Required.Reservation, receipt) {
			return c, store.ErrCorrupt
		}
		return c, nil
	}
	copy := receipt
	copy.Postings = slices.Clone(receipt.Postings)
	c.Required = &RequiredSourceHold{Reservation: copy}
	if e = validateRequiredSourceCase(c, domain.Time(now.UnixNano())); e != nil {
		return c, e
	}
	return s.append(c, actor, "hold_reserved", "durable_required_source_reservation", nil, "", "", nil, now)
}

// ResumeRequiredReserved は署名保存済み参照と現在元の照合後、固定copyを再開する。
// checkは各copy/完了の前に元所有列を待ち、現在認可/時計も再確認する。nilは拒否する。
func (s *Store) ResumeRequiredReserved(id, actor domain.ID, etag string, records []app.AcceptedEvidence, receipt app.RequiredHoldReceipt, now time.Time, check func() error) (Case, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if e = requiredReservedCopyReady(c, receipt, now, check); e != nil {
		return c, e
	}
	if e = check(); e != nil {
		return c, e
	}
	c, e = s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.State == "active" {
		_, e = s.Records(c, now)
		return c, e
	}
	updated, e := s.resumeHoldChecked(c, actor, records, now, check)
	if e != nil {
		if saved, err := s.Get(id); err == nil {
			return saved, e
		}
	}
	return updated, e
}

func requiredReservedCopyReady(c Case, receipt app.RequiredHoldReceipt, now time.Time, check func() error) error {
	if requiredExtensionPending(c) || check == nil || c.Required == nil || c.Required.Released != nil {
		return ErrInvalid
	}
	if !sameRequiredReceipt(c.Required.Reservation, receipt) || receipt.Binding.Until <= domain.Time(now.UnixNano()) {
		return store.ErrCorrupt
	}
	return nil
}

func sameRequiredReceipt(a, b app.RequiredHoldReceipt) bool {
	return a.Binding == b.Binding && a.Sequence == b.Sequence && a.SHA == b.SHA && a.At == b.At && a.State == b.State && slices.Equal(a.Postings, b.Postings)
}
