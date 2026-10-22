// 先行案件intentと元所有列の耐久予約を照合し、予約済み原本のコピー再開を提供する。
package disclosure

import (
	"encoding/json"
	"slices"
	"time"

	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
)

func validateHTTPReservationShape(h *HTTPHold) error {
	r := h.Reservation
	if r == nil {
		return nil
	}
	if r.Binding.Unbound != h.Unbound || r.Site != h.Site || r.Sequence == 0 || r.SHA == (domain.Hash{}) || r.At < h.Captured || r.State != "active" || r.Binding.Case == (domain.ID{}) || r.Binding.Revision == 0 || r.Binding.Until <= r.At || len(r.Items) != len(h.Items) {
		return store.ErrCorrupt
	}
	for i, item := range h.Items {
		ref := r.Items[i]
		if item.Record != ref.Record || item.Source != ref.SHA || item.Expires != ref.Expires || ref.Sequence == 0 || ref.Day == 0 {
			return store.ErrCorrupt
		}
	}
	return nil
}

// HTTPReservationBinding は先行intentの固定集合に対応する元所有列向け範囲を作る。
func (s *Store) HTTPReservationBinding(c Case, now time.Time) (evidence.OptionalHoldBinding, error) {
	current, e := s.AuthorizeState(c.ID, c.ETag(), now)
	if e != nil {
		return evidence.OptionalHoldBinding{}, e
	}
	if current.Extension != nil && current.Extension.State == "pending" {
		return evidence.OptionalHoldBinding{}, ErrConflict
	}
	if current.HTTP == nil || current.HTTP.State != "preparing" && current.HTTP.State != "partial" {
		return evidence.OptionalHoldBinding{}, ErrConflict
	}
	if current.HTTP.Unbound {
		return evidence.OptionalHoldBinding{Unbound: true, Case: c.ID, Revision: current.Revision, Board: c.Scope.Board, From: c.Scope.From, To: c.Scope.To, Operations: []domain.ID{}, Until: c.Until}, nil
	}
	rows, e := s.Records(current, now)
	if e != nil {
		return evidence.OptionalHoldBinding{}, e
	}
	operations := make([]domain.ID, 0, len(rows))
	for _, row := range rows {
		operations = append(operations, row.Operation)
	}
	return evidence.OptionalHoldBinding{Case: c.ID, Revision: current.Revision, Board: c.Scope.Board, From: c.Scope.From, To: c.Scope.To, Unbound: c.HTTP.Unbound, Operations: operations, Until: c.Until}, nil
}

// validateHTTPReservation は期待案件/範囲とコピー対象を耐久参照へ照合する。
func (s *Store) validateHTTPReservation(c Case, receipt evidence.OptionalHoldReceipt, now time.Time) error {
	if c.HTTP == nil || receipt.Site != c.HTTP.Site || receipt.Binding.Case != c.ID || receipt.Binding.Revision > c.Revision || receipt.Binding.Board != c.Scope.Board || receipt.Binding.From != c.Scope.From || receipt.Binding.To != c.Scope.To || receipt.Binding.Until != c.Until || receipt.Binding.Until <= max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano())) {
		return store.ErrCorrupt
	}
	h := *c.HTTP
	h.Reservation = &receipt
	if e := validateHTTPReservationShape(&h); e != nil {
		return e
	}
	if c.HTTP.Unbound {
		if !receipt.Binding.Unbound || len(receipt.Binding.Operations) != 0 {
			return store.ErrCorrupt
		}
		return nil
	}
	rows, e := s.Records(c, now)
	if e != nil {
		return e
	}
	ops := make([]domain.ID, 0, len(rows))
	for _, row := range rows {
		ops = append(ops, row.Operation)
	}
	if !slices.Equal(ops, receipt.Binding.Operations) {
		return store.ErrCorrupt
	}
	return nil
}

// BindHTTPReservation は元予約Syncの後で、コピー前に耐久参照を案件へ署名保存する。
// 呼出元は元所有列から得た信頼済みreceiptと、現在の権限/reader42を検査する。
func (s *Store) BindHTTPReservation(id, actor domain.ID, etag string, receipt evidence.OptionalHoldReceipt, now time.Time) (Case, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.Extension != nil && c.Extension.State == "pending" {
		return c, ErrConflict
	}
	if c.HTTP == nil || c.HTTP.State != "preparing" && c.HTTP.State != "partial" {
		return c, ErrConflict
	}
	if e := s.validateHTTPReservation(c, receipt, now); e != nil {
		return c, e
	}
	if c.HTTP.Reservation != nil {
		old := c.HTTP.Reservation
		left, _ := json.Marshal(old)
		right, _ := json.Marshal(receipt)
		if string(left) == string(right) {
			return c, nil
		}
		if receipt.Sequence <= old.Sequence || receipt.Binding.Revision < old.Binding.Revision || receipt.Binding.Until < old.Binding.Until {
			return c, store.ErrCorrupt
		}
	}
	copy := receipt
	copy.Binding.Operations = slices.Clone(receipt.Binding.Operations)
	copy.Items = slices.Clone(receipt.Items)
	c.HTTP.Reservation = &copy
	return s.append(c, actor, "http_hold_reserved", "durable_http_source_reservation", nil, "", "", nil, now)
}

// ResumeHTTPReserved は元所有者で再照合済みの予約原本から固定copyを再開する。
// checkは各copyと完了署名の前に現在の元予約を照合する。nil/失効した参照で元期限を延長しない。
func (s *Store) ResumeHTTPReserved(id, actor domain.ID, etag string, entries []evidence.Entry, receipt evidence.OptionalHoldReceipt, now time.Time, check func() error) (Case, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.Extension != nil && c.Extension.State == "pending" {
		return c, ErrConflict
	}
	if check == nil || c.HTTP == nil || c.HTTP.Reservation == nil {
		return c, ErrInvalid
	}
	if e = check(); e != nil {
		return c, e
	}
	if e = s.validateHTTPReservation(c, receipt, now); e != nil {
		return c, e
	}
	left, _ := json.Marshal(c.HTTP.Reservation)
	right, _ := json.Marshal(receipt)
	if string(left) != string(right) {
		return c, store.ErrCorrupt
	}
	if c.HTTP.State == "active" {
		_, e = s.HTTPRecords(c, now)
		return c, e
	}
	if c.HTTP.State != "preparing" && c.HTTP.State != "partial" || len(entries) > evidence.MaxOptionalQueryRecords {
		return c, ErrConflict
	}
	ops, e := s.httpOperations(c, now)
	if e != nil {
		return c, e
	}
	updated, err := s.resumeHTTPHold(c, actor, entries, ops, now, &receipt, check)
	if err != nil {
		if saved, getErr := s.Get(id); getErr == nil {
			return saved, err
		}
	}
	return updated, err
}
