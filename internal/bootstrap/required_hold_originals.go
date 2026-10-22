// 有効な必須予約の両側原本が元位置/hashに現存することを、回収再開前に非変更で検査する。
package bootstrap

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"oimobbs/internal/app"
	"oimobbs/internal/disclosure"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"path/filepath"
	"slices"
)

type requiredOriginalExpectation struct {
	Sequence domain.U64
	SHA      domain.Hash
	Kind     string
}

type requiredOriginalDay map[domain.ID]requiredOriginalExpectation

// inspectRequiredHeldOriginalsWithCases は照合済み先行承認を回収期限へ投影して物理原本を検査する。
// 投影は読取り検査内だけで使い、署名済み元参照や開示期限を更新しない。
func inspectRequiredHeldOriginalsWithCases(root string, key ed25519.PrivateKey, receipts []app.RequiredHoldReceipt, cases []disclosure.RequiredCaseInspection, now domain.Time) error {
	projected, e := requiredOriginalInspectionLeases(receipts, cases)
	if e != nil {
		return e
	}
	return inspectRequiredHeldOriginals(root, key, projected, now)
}

// requiredOriginalInspectionLeases は更新前の非終端pending元を署名済み新回収期限まで検査対象にする。
func requiredOriginalInspectionLeases(receipts []app.RequiredHoldReceipt, cases []disclosure.RequiredCaseInspection) ([]app.RequiredHoldReceipt, error) {
	until := map[domain.ID]domain.Time{}
	for _, row := range cases {
		c := row.Current
		if c.RequiredExtension == nil || c.RequiredExtension.State != "pending" {
			continue
		}
		if c.State != "preparing" && c.State != "partial" {
			continue
		}
		if _, found := until[c.ID]; found {
			return nil, store.ErrCorrupt
		}
		until[c.ID] = c.RetentionUntil()
	}
	result := slices.Clone(receipts)
	for i := range result {
		r := &result[i]
		if r.State == "active" {
			r.Binding.Until = max(r.Binding.Until, until[r.Binding.Case])
		}
	}
	return result, nil
}

// inspectRequiredHeldOriginals は保護期限内のactive予約だけを照合する。原本文を結果へ返さない。
func inspectRequiredHeldOriginals(root string, key ed25519.PrivateKey, receipts []app.RequiredHoldReceipt, now domain.Time) error {
	expected, e := requiredOriginalExpectations(receipts, now)
	if e != nil {
		return e
	}
	for board, days := range expected {
		for day, ids := range days {
			if e = inspectRequiredOriginalDay(root, key, board, day, ids, now); e != nil {
				return e
			}
		}
	}
	return nil
}

// requiredOriginalExpectations は保護期限内の両側位置を重複排除し、異なる元参照の混入を拒否する。
func requiredOriginalExpectations(receipts []app.RequiredHoldReceipt, now domain.Time) (map[domain.ID]map[uint64]requiredOriginalDay, error) {
	result := map[domain.ID]map[uint64]requiredOriginalDay{}
	for _, r := range receipts {
		if r.State != "active" || r.Binding.Until <= now {
			continue
		}
		if result[r.Binding.Board] == nil {
			result[r.Binding.Board] = map[uint64]requiredOriginalDay{}
		}
		for _, p := range r.Postings {
			if e := addRequiredOriginalExpectation(result[r.Binding.Board], p.Proposal, p.Identity.ProposalID, p.Identity.ProposalSHA, "evidence_proposal"); e != nil {
				return nil, e
			}
			if e := addRequiredOriginalExpectation(result[r.Binding.Board], p.Decision, p.Identity.DecisionID, p.Identity.DecisionSHA, "evidence_decision"); e != nil {
				return nil, e
			}
		}
	}
	return result, nil
}

// addRequiredOriginalExpectation は同じ元IDの位置/hashが全案件で一致する場合だけ参照集合へ加える。
func addRequiredOriginalExpectation(days map[uint64]requiredOriginalDay, source app.RequiredHoldSource, id domain.ID, sha domain.Hash, kind string) error {
	day := uint64(source.Day)
	if days[day] == nil {
		days[day] = requiredOriginalDay{}
	}
	next := requiredOriginalExpectation{Sequence: source.Sequence, SHA: sha, Kind: kind}
	if old, exists := days[day][id]; exists && old != next {
		return store.ErrCorrupt
	}
	days[day][id] = next
	return nil
}

// inspectRequiredOriginalDay は署名/source/連鎖と予約位置を照合し、回収済み原本の救済を許さない。
func inspectRequiredOriginalDay(root string, key ed25519.PrivateKey, board domain.ID, day uint64, expected requiredOriginalDay, now domain.Time) error {
	path := filepath.Join(root, "evidence", board.String(), fmt.Sprint(day))
	if e := inspectPostingJournalDirectory(path); e != nil {
		return e
	}
	inspection, e := evidence.VisitJournalReadOnly(path, board, day, 10, key, app.PostingValidator(strictjson.Validate), func(entry evidence.Entry) error {
		ref, found := expected[entry.Event.RecordID]
		if !found {
			return nil
		}
		var position struct {
			Sequence domain.U64 `json:"source_control_seq"`
		}
		if json.Unmarshal(entry.Payload, &position) != nil || position.Sequence != ref.Sequence || entry.Event.EventSHA != ref.SHA || entry.Event.Kind != ref.Kind {
			return store.ErrCorrupt
		}
		delete(expected, entry.Event.RecordID)
		return nil
	})
	if e != nil {
		return e
	}
	if e = checkRequiredJournalBoundary(inspection, true, now); e != nil {
		return e
	}
	if len(expected) != 0 {
		return app.ErrEvidenceGap
	}
	return nil
}
