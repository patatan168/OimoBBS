// 未受理の接続・結果を既存案件のコピー領域へ保全し、固定intentから再開する。
package disclosure

import (
	"crypto/sha256"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"reflect"
	"slices"
	"time"
)

// RejectedHold は本文を持たない固定対象。未完成intent自体を元GCの耐久保護へ使用する。
type RejectedHold struct {
	Captured domain.Time          `json:"captured_at_ns"`
	State    string               `json:"state"`
	Sources  []app.RejectedSource `json:"sources"`
	Items    []Item               `json:"items"`
}

// PrepareRejectedHold は通常期限内の固定対象と元署名hashをコピー前にSyncする。
// GCはこの署名済みintentを照合して、未完成の元操作だけを案件期限まで保護する。
func (s *Store) PrepareRejectedHold(id, actor domain.ID, etag, key, purpose string, rows []app.RejectedEvidence, now time.Time) (Case, error) {
	input := struct {
		Purpose string `json:"purpose"`
	}{purpose}
	if c, replay, e := s.Replay(id, actor, "rejected_hold_intent", etag, key, input); e != nil {
		return c, e
	} else if replay {
		return s.currentPreparedHold(c.ID)
	}
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.Rejected != nil {
		return s.prepareExistingRejectedHold(c, actor, etag, key, purpose, input, now)
	}
	h, e := newRejectedHold(c, rows, now)
	if e != nil {
		return c, e
	}
	c.Rejected, c.State = h, "preparing"
	c, e = s.append(c, actor, "rejected_hold_intent", purpose, nil, etag, key, input, now)
	if e != nil {
		return c, e
	}
	return c, s.after("hold:intent")
}

// ResumeRejectedHold は板所有列で再検査済みの固定投影をコピーし、全件一致時だけactiveにする。
// checkは元所有列の現在性と案件CAS/権限を各copy直前と完成前に検査する。
func (s *Store) ResumeRejectedHold(id, actor domain.ID, etag string, rows []app.RejectedEvidence, now time.Time, check func() error) (Case, error) {
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.Rejected == nil || check == nil {
		return c, ErrInvalid
	}
	if c.Rejected.State == "active" {
		_, e := s.RejectedRecords(c, now)
		return c, e
	}
	if c.Rejected.State != "preparing" || c.State != "preparing" {
		return c, ErrConflict
	}
	if e = s.beginRejectedHoldCopy(c, now, check); e != nil {
		return c, e
	}
	c, e = s.copyRejectedHoldItems(c, rows, now, check)
	if e != nil {
		return c, e
	}

	if e = s.checkRequiredCopyGuard(c.ID, c.Revision, now, check); e != nil {
		return c, e
	}
	c.Rejected.State, c.State = "active", "active"
	return s.append(c, actor, "rejected_hold_complete", "rejected_connection_copy", nil, "", "", nil, now)
}

// matchRejectedHoldSources は元の通常期限が過ぎた場合も先行intentの固定対象だけを許可する。
func matchRejectedHoldSources(c Case, rows []app.RejectedEvidence) ([]app.RejectedEvidence, error) {
	available := map[domain.ID]app.RejectedEvidence{}
	for _, row := range rows {
		if MatchesRejected(c.Scope, row) {
			available[row.RecordID] = row
		}
	}
	result := make([]app.RejectedEvidence, 0, len(c.Rejected.Sources))
	for _, ref := range c.Rejected.Sources {
		row, found := available[ref.Record]
		if !found || row.Source() != ref {
			return nil, ErrExpired
		}
		result = append(result, row)
	}
	return result, nil
}

// RejectedRecords は案件の署名済みhashと固定元を照合して期限内の保全コピーを返す。
func (s *Store) RejectedRecords(c Case, now time.Time) ([]app.RejectedEvidence, error) {
	if c.Rejected == nil || c.Rejected.State != "active" || c.State != "active" || domain.Time(now.UnixNano()) >= c.RetentionUntil() {
		return nil, ErrExpired
	}
	return s.readRejectedHeldRecords(c)
}

// readRejectedHeldRecords は開示認可と別に、起動/GC前にも保全コピーの物理対応を検査する。
func (s *Store) readRejectedHeldRecords(c Case) ([]app.RejectedEvidence, error) {
	result := make([]app.RejectedEvidence, 0, len(c.Rejected.Items))
	for i, item := range c.Rejected.Items {
		raw, e := readArtifact(s.itemPath(c.ID, item.Record))
		if e != nil {
			return nil, e
		}
		if item.State != "held" || sha256.Sum256(raw) != item.SHA {
			return nil, store.ErrCorrupt
		}
		row, e := app.DecodeRejectedSnapshot(raw)
		if e != nil || row.Source() != c.Rejected.Sources[i] || !MatchesRejected(c.Scope, row) {
			return nil, store.ErrCorrupt
		}
		result = append(result, row)
	}
	return result, nil
}

// validateRejectedHold は本文なし固定参照とコピー状態を完全型で検査する。
func validateRejectedHold(c Case, at domain.Time) error {
	h := c.Rejected
	if h == nil {
		return nil
	}
	if !validRejectedHoldBounds(c, at) {
		return store.ErrCorrupt
	}
	if !slices.Contains([]string{"preparing", "active", "removed"}, h.State) || len(c.Items) != 0 || c.Required != nil || c.HTTP != nil {
		return store.ErrCorrupt
	}
	return validateRejectedHoldItems(h)
}

// validateRejectedHoldItems は期限前の固定対象・両署名hash・コピーhashを照合する。
func validateRejectedHoldItems(h *RejectedHold) error {
	seen := map[domain.ID]bool{}
	for i, ref := range h.Sources {
		item := h.Items[i]
		if !validRejectedSourceRef(ref, h.Captured+1, seen) || item.Record != ref.Record || item.Source != ref.ProposalSHA || item.Expires != ref.Until {
			return store.ErrCorrupt
		}
		if !validRejectedHoldItemState(h.State, item) {
			return store.ErrCorrupt
		}
		seen[ref.Record] = true
	}
	return nil
}

// validRejectedHoldItemState は署名済み状態とコピーhashの有無を一致させる。
func validRejectedHoldItemState(state string, item Item) bool {
	switch state {
	case "preparing":
		return item.State == "pending" && item.SHA == (domain.Hash{})
	case "active":
		return item.State == "held" && item.SHA != (domain.Hash{})
	case "removed":
		return item.State == "removed"
	default:
		return false
	}
}

// validateRejectedHoldTransition は固定対象の差替えと解除後の復活を拒否する。
func validateRejectedHoldTransition(old, next Case, action string) error {
	a, b := old.Rejected, next.Rejected
	if a == nil {
		if b == nil {
			return nil
		}
		if action != "rejected_hold_intent" || b.State != "preparing" {
			return store.ErrCorrupt
		}
		return nil
	}
	if !stableRejectedHold(a, b) {
		return store.ErrCorrupt
	}
	if reflect.DeepEqual(a, b) {
		return nil
	}
	if allowedRejectedHoldChange(a, b, action) {
		return nil
	}
	return store.ErrCorrupt
}

// prepareExistingRejectedHold は未完成の固定intentを変更せず、新しい要求で再開する。
func (s *Store) prepareExistingRejectedHold(c Case, actor domain.ID, etag, key, purpose string, input any, now time.Time) (Case, error) {
	if c.Rejected.State == "active" {
		_, e := s.RejectedRecords(c, now)
		return c, e
	}
	if c.Rejected.State != "preparing" || c.State != "preparing" {
		return c, ErrExpired
	}
	return s.append(c, actor, "rejected_hold_intent", purpose, nil, etag, key, input, now)
}

// newRejectedHold は保全前の通常期限を検査してコピー対象を固定する。
func newRejectedHold(c Case, rows []app.RejectedEvidence, now time.Time) (*RejectedHold, error) {
	if c.State != "draft" || len(c.Items) != 0 || c.Required != nil || c.HTTP != nil {
		return nil, ErrConflict
	}
	sources, _, e := rejectedExportSources(c, rows, now)
	if e != nil {
		return nil, e
	}
	h := &RejectedHold{Captured: domain.Time(now.UnixNano()), State: "preparing", Sources: sources, Items: []Item{}}
	for _, ref := range sources {
		h.Items = append(h.Items, Item{Record: ref.Record, Source: ref.ProposalSHA, Expires: ref.Until, State: "pending"})
	}
	return h, nil
}

// beginRejectedHoldCopy は現在案件・容量を検査して既存コピー領域を準備する。
func (s *Store) beginRejectedHoldCopy(c Case, now time.Time, check func() error) error {
	if e := s.requireCapacity(MaxArtifactBytes); e != nil {
		return e
	}
	if e := s.checkRequiredCopyGuard(c.ID, c.Revision, now, check); e != nil {
		return e
	}
	return prepareDir(s.artifactDir(c.ID, "items"))
}

// copyRejectedHoldItems は固定対象を再照合し、各コピー前に現在認可/CASを検査する。
func (s *Store) copyRejectedHoldItems(c Case, rows []app.RejectedEvidence, now time.Time, check func() error) (Case, error) {
	selected, e := matchRejectedHoldSources(c, rows)
	if e != nil {
		return c, e
	}
	for i, row := range selected {
		raw, e := app.EncodeRejectedSnapshot(row)
		if e != nil {
			return c, e
		}
		if e = s.checkRequiredCopyGuard(c.ID, c.Revision, now, check); e != nil {
			return c, e
		}
		if e = writeArtifact(s.itemPath(c.ID, row.RecordID), raw); e != nil {
			return c, e
		}
		c.Rejected.Items[i].SHA, c.Rejected.Items[i].State = sha256.Sum256(raw), "held"
		if e = s.after("hold:copy"); e != nil {
			return c, e
		}
	}
	return c, nil
}

// validRejectedHoldBounds は署名時刻と対象数を制限する。
func validRejectedHoldBounds(c Case, at domain.Time) bool {
	h := c.Rejected
	return h.Captured >= c.Created && h.Captured <= at && len(h.Sources) > 0 && len(h.Sources) <= MaxRecords && len(h.Items) == len(h.Sources)
}

// stableRejectedHold は固定対象・初回時刻の差替えを拒否する。
func stableRejectedHold(a, b *RejectedHold) bool {
	return b != nil && a.Captured == b.Captured && reflect.DeepEqual(a.Sources, b.Sources)
}

// allowedRejectedHoldChange はコピー完成と解除回収だけを状態変更として許可する。
func allowedRejectedHoldChange(a, b *RejectedHold, action string) bool {
	switch action {
	case "rejected_hold_complete":
		return a.State == "preparing" && b.State == "active"
	case "cleanup":
		return b.State == "removed"
	default:
		return false
	}
}
