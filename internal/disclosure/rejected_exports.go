// 通常期限内の未受理接続/結果を固定対象へ束縛し、既存ZIP/一回取得へ接続する。
package disclosure

import (
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"reflect"
	"slices"
	"time"
)

const rejectedExportKind = "not_accepted"

// scopeMatchesRejectedSource は元proposalの固定IDへ案件範囲を照合する。
func scopeMatchesRejectedSource(scope Scope, board domain.ID, thread domain.U64, at domain.Time, id domain.ID) bool {
	return board == scope.Board && (scope.Thread == 0 || scope.Thread == thread) && at >= scope.From && at < scope.To && (len(scope.Records) == 0 || slices.Contains(scope.Records, id))
}

// caseHasRejectedExports は未受理提出の追加形式が必要な案件を識別する。
func caseHasRejectedExports(c Case) bool {
	for _, v := range c.Exports {
		if v.Kind == rejectedExportKind {
			return true
		}
	}
	return false
}

// GenerateRejected は最大100件の元両署名hashを先行intentへ固定し、接続/結果のZIPを作る。
// 保全コピーは作らず、元の7日期限・案件期限・生成後24時間の最短を提出物期限にする。
func (s *Store) GenerateRejected(id, actor domain.ID, etag, key, purpose string, columns []string, rows []app.RejectedEvidence, now time.Time) (Case, Export, error) {
	if !app.ValidRejectedColumns(columns) {
		return Case{}, Export{}, ErrInvalid
	}
	input := struct {
		Kind    string   `json:"record_kind"`
		Purpose string   `json:"purpose"`
		Columns []string `json:"columns"`
	}{rejectedExportKind, purpose, columns}
	c, replay, e := s.Replay(id, actor, "export_intent", etag, key, input)
	if e != nil {
		return c, Export{}, e
	}
	if !replay {
		c, e = s.AuthorizeState(id, etag, now)
		if e != nil {
			return c, Export{}, e
		}
		c, e = s.prepareRejectedExport(c, actor, etag, key, purpose, columns, rows, input, now)
		if e != nil {
			return c, Export{}, e
		}
	}
	current, e := s.Get(id)
	if e != nil {
		return current, Export{}, e
	}
	index, e := rejectedExportIndex(current, s.IDFor(actor, "rejected-export:"+key))
	if e != nil {
		return current, Export{}, e
	}
	return s.generateRejectedExisting(current, index, actor, purpose, rows, now)
}

// prepareRejectedExport は通常期限内の固定対象をZIP作成前に署名保存する。
func (s *Store) prepareRejectedExport(c Case, actor domain.ID, etag, key, purpose string, columns []string, rows []app.RejectedEvidence, input any, now time.Time) (Case, error) {
	if c.HTTP != nil && c.HTTP.Unbound {
		return c, ErrConflict
	}
	if c.State != "draft" && c.State != "active" && c.State != "partial" {
		return c, ErrConflict
	}
	if len(c.Exports) >= 100 {
		return c, ErrLimit
	}
	sources, until, e := rejectedExportSources(c, rows, now)
	if e != nil {
		return c, e
	}
	v := Export{RejectedHeld: c.Rejected != nil && c.Rejected.State == "active", ID: s.IDFor(actor, "rejected-export:"+key), Kind: rejectedExportKind, RejectedSources: sources, Created: domain.Time(now.UnixNano()), Until: until, Columns: append([]string{}, columns...), State: "preparing"}
	c.Exports = append(c.Exports, v)
	c, e = s.append(c, actor, "export_intent", purpose, columns, etag, key, input, now)
	if e != nil {
		return c, e
	}
	return c, s.after("export:intent")
}

// rejectedExportSources は対象の欠落・重複を拒否し、最短の元期限へ提出物を限定する。
func rejectedExportSources(c Case, rows []app.RejectedEvidence, now time.Time) ([]app.RejectedSource, domain.Time, error) {
	until := min(c.Until, domain.Time(now.Add(24*time.Hour).UnixNano()))
	if c.State == "draft" {
		until = min(until, c.Created+domain.Time(7*24*time.Hour))
	}
	if len(rows) == 0 || len(rows) > MaxRecords {
		return nil, 0, ErrLimit
	}
	sources := make([]app.RejectedSource, 0, len(rows))
	seen := map[domain.ID]bool{}
	for _, r := range rows {
		if !validRejectedHoldSourceRow(c, r, seen, now) {
			return nil, 0, ErrExpired
		}
		if _, e := r.Project(nil); e != nil {
			return nil, 0, e
		}
		seen[r.RecordID] = true
		sources = append(sources, r.Source())
		until = min(until, rejectedRecordUntil(c, r))
	}
	if len(c.Scope.Records) != 0 && len(sources) != len(c.Scope.Records) {
		return nil, 0, ErrExpired
	}
	return sources, until, nil
}

// ResumeRejectedExport は固定対象を現在元へ再照合し、元の期限で同じ提出物を再開する。
func (s *Store) ResumeRejectedExport(id, export, actor domain.ID, etag, key, purpose string, rows []app.RejectedEvidence, now time.Time) (Case, Export, error) {
	input := struct {
		ID      domain.ID `json:"export_id"`
		Purpose string    `json:"purpose"`
	}{export, purpose}
	c, replay, e := s.Replay(id, actor, "export_resume", etag, key, input)
	if e != nil {
		return c, Export{}, e
	}
	if !replay {
		c, e = s.AuthorizeState(id, etag, now)
		if e != nil {
			return c, Export{}, e
		}
	}
	c, e = s.Get(id)
	if e != nil {
		return c, Export{}, e
	}
	index, e := rejectedExportIndex(c, export)
	if e != nil {
		return c, Export{}, e
	}
	if c.Exports[index].State != "preparing" {
		return c, c.Exports[index], nil
	}
	if !replay {
		c, e = s.append(c, actor, "export_resume", purpose, c.Exports[index].Columns, etag, key, input, now)
		if e != nil {
			return c, Export{}, e
		}
	}
	return s.generateRejectedExisting(c, index, actor, purpose, rows, now)
}

// rejectedExportIndex は受理投稿の提出物を未受理の再開経路へ混ぜない。
func rejectedExportIndex(c Case, id domain.ID) (int, error) {
	for i, v := range c.Exports {
		if v.ID == id && v.Kind == rejectedExportKind {
			return i, nil
		}
	}
	return 0, ErrInvalid
}

// generateRejectedExisting は保存済み対象を照合し、同じ期限でZIPを再開する。
func (s *Store) generateRejectedExisting(c Case, index int, actor domain.ID, purpose string, rows []app.RejectedEvidence, now time.Time) (Case, Export, error) {
	v := c.Exports[index]
	if domain.Time(now.UnixNano()) >= min(v.Until, c.Until) || c.State == "closed" || c.State == "releasing" {
		return c, v, ErrExpired
	}
	if v.State != "preparing" {
		return c, v, nil
	}
	rows, e := s.rejectedExportRows(c, v, rows, now)
	if e != nil {
		return c, v, e
	}
	selected, e := matchRejectedExportSources(c, v, rows, now)
	if e != nil {
		return c, v, e
	}
	if e = s.requireCapacity(MaxArtifactBytes); e != nil {
		return c, v, e
	}
	if e = prepareDir(s.artifactDir(c.ID, "exports")); e != nil {
		return c, v, e
	}
	return s.publishRejectedExport(c, index, actor, purpose, selected, now)
}

// matchRejectedExportSources は元原本が接続行へ移った後も固定両署名hashを照合する。
func matchRejectedExportSources(c Case, v Export, rows []app.RejectedEvidence, now time.Time) ([]app.RejectedEvidence, error) {
	available := map[domain.ID]app.RejectedEvidence{}
	for _, row := range rows {
		if MatchesRejected(c.Scope, row) {
			available[row.RecordID] = row
		}
	}
	result := make([]app.RejectedEvidence, 0, len(v.RejectedSources))
	for _, ref := range v.RejectedSources {
		row, ok := available[ref.Record]
		if !ok || row.Source() != ref || rejectedRecordUntil(c, row) <= domain.Time(now.UnixNano()) {
			return nil, ErrExpired
		}
		result = append(result, row)
	}
	return result, nil
}

// finishRejectedExport は完成時にも期限を確認してから生成物hashを署名保存する。
func (s *Store) finishRejectedExport(c Case, index int, actor domain.ID, purpose string, now time.Time) (Case, Export, error) {
	v := c.Exports[index]
	finished := time.Now()
	if finished.Before(now) || domain.Time(finished.UnixNano()) >= min(v.Until, c.Until) {
		return c, v, ErrExpired
	}
	sha, bytes, e := hashArtifact(s.exportPath(c.ID, v.ID))
	if e != nil {
		return c, v, e
	}
	v.SHA, v.Bytes, v.State = sha, domain.U64(bytes), "ready"
	c.Exports[index] = v
	c, e = s.append(c, actor, "export_ready", purpose, v.Columns, "", "", nil, now)
	return c, v, e
}

// validateRejectedCaseAudit は未受理照会・提出の追加列と固定参照を検査する。
func validateRejectedCaseAudit(a Audit) error {
	if a.Action == "rejected_query" && !app.ValidRejectedColumns(a.Columns) {
		return store.ErrCorrupt
	}
	for _, v := range a.Case.Exports {
		if v.Kind == "" {
			if len(v.RejectedSources) != 0 {
				return store.ErrCorrupt
			}
			continue
		}
		if v.Kind == "http_observation" {
			if e := validateHTTPObservationExport(a.Case, v); e != nil {
				return e
			}
			continue
		}
		if !validRejectedHeldExport(a.Case, v) {
			return store.ErrCorrupt
		}
		if e := validateRejectedExport(v); e != nil {
			return e
		}
	}
	return nil
}

// validateRejectedExport は保存済み未受理提出の種別・対象・期限を検査する。
func validateRejectedExport(v Export) error {
	if v.Kind != rejectedExportKind || len(v.RejectedSources) == 0 || len(v.RejectedSources) > MaxRecords || !app.ValidRejectedColumns(v.Columns) || !validRejectedExportMetadata(v) {
		return store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, ref := range v.RejectedSources {
		if !validRejectedSourceRef(ref, rejectedReferenceMinimum(v), seen) {
			return store.ErrCorrupt
		}
		seen[ref.Record] = true
	}
	return nil
}

// validateRejectedExportTransition は通常操作でも未受理提出物の固定対象を変更させない。
func validateRejectedExportTransition(previous, next Case, action string) error {
	old := map[domain.ID]Export{}
	for _, v := range previous.Exports {
		old[v.ID] = v
	}
	for _, v := range next.Exports {
		prior, found := old[v.ID]
		if !found {
			if v.Kind != "" && action != "export_intent" {
				return store.ErrCorrupt
			}
			continue
		}
		if prior.Kind != v.Kind || prior.HTTPSelection != v.HTTPSelection || prior.RejectedHeld != v.RejectedHeld || prior.Kind != "" && !reflect.DeepEqual(prior.RejectedSources, v.RejectedSources) {
			return store.ErrCorrupt
		}
	}
	return nil
}

// validRejectedSourceRow は固定対象と元ログ期限を提出intent保存前に検査する。
func validRejectedSourceRow(scope Scope, r app.RejectedEvidence, seen map[domain.ID]bool, now time.Time) bool {
	return MatchesRejected(scope, r) && !seen[r.RecordID] && r.Expires > domain.Time(now.UnixNano())
}

// validRejectedSourceRef は保存済み参照の必須識別子と期限を検査する。
func validRejectedSourceRef(ref app.RejectedSource, until domain.Time, seen map[domain.ID]bool) bool {
	return ref.Record != (domain.ID{}) && !seen[ref.Record] && ref.ProposalSHA != (domain.Hash{}) && ref.DecisionSHA != (domain.Hash{}) && ref.Until >= until
}

// validRejectedExportMetadata は通常期限内の提出物の識別子・時間・状態を検査する。
func validRejectedExportMetadata(v Export) bool {
	return v.ID != (domain.ID{}) && v.Created > 0 && v.Until > v.Created && v.Until-v.Created <= domain.Time(24*time.Hour) && slices.Contains([]string{"preparing", "ready", "consumed", "removed"}, v.State)
}

// rejectedRecordUntil は案件保全された固定元だけを案件期限へ延長する。
func rejectedRecordUntil(c Case, row app.RejectedEvidence) domain.Time {
	if c.Rejected != nil && c.Rejected.State == "active" && slices.Contains(c.Rejected.Sources, row.Source()) {
		return c.RetentionUntil()
	}
	return row.Expires
}

// rejectedReferenceMinimum は保全後も元の7日期限を参照へ残す。
func rejectedReferenceMinimum(v Export) domain.Time {
	if v.RejectedHeld {
		return 1
	}
	return v.Until
}

// validRejectedHoldSourceRow は固定範囲と通常/案件期限を照合する。
func validRejectedHoldSourceRow(c Case, row app.RejectedEvidence, seen map[domain.ID]bool, now time.Time) bool {
	return MatchesRejected(c.Scope, row) && !seen[row.RecordID] && rejectedRecordUntil(c, row) > domain.Time(now.UnixNano())
}

// rejectedExportRows は保全された提出物を必ず案件コピーから生成する。
func (s *Store) rejectedExportRows(c Case, v Export, rows []app.RejectedEvidence, now time.Time) ([]app.RejectedEvidence, error) {
	if v.RejectedHeld {
		return s.RejectedRecords(c, now)
	}
	return rows, nil
}

// publishRejectedExport はコピー対象確定後にZIPを同期し、完成hashを署名保存する。
func (s *Store) publishRejectedExport(c Case, index int, actor domain.ID, purpose string, selected []app.RejectedEvidence, now time.Time) (Case, Export, error) {
	v := c.Exports[index]
	if e := s.writeRejectedZIP(c, v, actor, selected, now); e != nil {
		return c, v, e
	}
	if e := s.after("export:file"); e != nil {
		return c, v, e
	}
	return s.finishRejectedExport(c, index, actor, purpose, now)
}

// validRejectedHeldExport は保全提出の参照を案件の固定元へ照合する。
func validRejectedHeldExport(c Case, v Export) bool {
	if !v.RejectedHeld {
		return true
	}
	if c.Rejected == nil {
		return false
	}
	for _, ref := range v.RejectedSources {
		if !slices.Contains(c.Rejected.Sources, ref) {
			return false
		}
	}
	return true
}
