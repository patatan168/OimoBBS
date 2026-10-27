// 原本回収を再開する前の案件照合用に、署名予約metadataを変更せず読み込む。
package app

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"os"
	"slices"
)

// RequiredHoldsInspection は全予約署名/連鎖/CAS検証済みの固定metadataと時計床。
type RequiredHoldsInspection struct {
	MinimumReader uint32
	Floor         domain.Time
	Receipts      []RequiredHoldReceipt
	Renewals      []RequiredHoldRenewalReceipt
}

// InspectRequiredOriginalHolds は私有領域/署名/CASを読取り専用検査する。欠落/不明元を補完しない。
// 現在案件との横断照合・元原本の存在照合は、回収を始める所有者が別に行う。
func InspectRequiredOriginalHolds(path string, board domain.ID, keyID uint32, key ed25519.PrivateKey) (RequiredHoldsInspection, error) {
	if board == (domain.ID{}) {
		return RequiredHoldsInspection{}, store.ErrCorrupt
	}
	if e := inspectRequiredHoldsBeforeOpen(path, true); e != nil {
		return RequiredHoldsInspection{}, e
	}
	h := &RequiredOriginalHolds{board: board, holds: map[domain.ID]RequiredHoldReceipt{}}
	if _, e := evidence.VisitJournalReadOnly(path, requiredHoldsOwner(board), requiredHoldsDay, keyID, key, requiredHoldValidator(board), h.replayEntry); e != nil {
		return RequiredHoldsInspection{}, e
	}
	if !h.initialized {
		return RequiredHoldsInspection{}, store.ErrCorrupt
	}
	result := RequiredHoldsInspection{MinimumReader: max(uint32(46), h.minimumReader), Floor: h.floor, Receipts: make([]RequiredHoldReceipt, 0, len(h.holds))}
	for _, r := range h.holds {
		r.Postings = slices.Clone(r.Postings)
		result.Receipts = append(result.Receipts, r)
	}
	for id := range h.renewals {
		renewal, found, e := h.RenewalReceipt(id)
		if e != nil || !found {
			return RequiredHoldsInspection{}, store.ErrCorrupt
		}
		result.Renewals = append(result.Renewals, renewal)
	}
	slices.SortFunc(result.Renewals, func(a, b RequiredHoldRenewalReceipt) int {
		return bytes.Compare(a.Current.Binding.Case[:], b.Current.Binding.Case[:])
	})
	slices.SortFunc(result.Receipts, func(a, b RequiredHoldReceipt) int { return bytes.Compare(a.Binding.Case[:], b.Binding.Case[:]) })
	return result, nil
}

func inspectRequiredHoldDirectory(path string) error {
	m, e := store.InspectControlManifest(path)
	if e != nil {
		return e
	}
	dir, e := os.Open(path)
	if e != nil {
		return e
	}
	defer dir.Close()
	entries, e := dir.ReadDir(4)
	if e != nil && e != io.EOF {
		return e
	}
	if len(entries) > 3 {
		return store.ErrCorrupt
	}
	for _, entry := range entries {
		name := entry.Name()
		known := name == "control.current" || name == m.Delta.File
		if m.Snapshot != nil {
			known = known || name == m.Snapshot.File
		}
		if !known {
			return store.ErrCorrupt
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return store.ErrCorrupt
		}
	}
	return nil
}
