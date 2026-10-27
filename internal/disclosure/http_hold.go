// 関連する署名済みHTTP原本を案件期限付きコピーへ保全し、固定intentから再開する。
package disclosure

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"time"

	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
)

// HTTPHold は本文やIPを持たず、固定対象・出所サイト・コピー結果を署名台帳へ残す。
// 全件コピー済みでも観測の完全性はpartial_observationのまま扱う。
type HTTPHold struct {
	Unbound     bool                          `json:"unbound_http"`
	Site        domain.ID                     `json:"site_id"`
	Captured    domain.Time                   `json:"captured_at_ns"`
	State       string                        `json:"state"`
	Items       []Item                        `json:"items"`
	Reservation *evidence.OptionalHoldReceipt `json:"source_reservation"`
	Released    *evidence.OptionalHoldReceipt `json:"source_release"`
}

func validateHTTPHold(h *HTTPHold, at domain.Time) error {
	if h == nil {
		return nil
	}
	if h.Site == (domain.ID{}) || h.Captured <= 0 || h.Captured > at || len(h.Items) > evidence.MaxOptionalQueryRecords || !slices.Contains([]string{"preparing", "active", "partial", "removed"}, h.State) {
		return ErrInvalid
	}
	seen := map[domain.ID]bool{}
	for _, item := range h.Items {
		if item.Record == (domain.ID{}) || item.Source == (domain.Hash{}) || item.Expires <= h.Captured || seen[item.Record] || !slices.Contains([]string{"pending", "held", "missing", "removed"}, item.State) || item.State == "held" && item.SHA == (domain.Hash{}) || h.State == "active" && item.State != "held" || h.State == "removed" && item.State != "removed" {
			return ErrInvalid
		}
		seen[item.Record] = true
	}
	if h.Reservation != nil {
		if e := validateHTTPReservationShape(h); e != nil {
			return e
		}
	}
	return validateHTTPReleaseShape(h)
}

// validateHTTPTransition は署名済み固定対象の差替えと保全済みhashの変更を拒否する。
func validateHTTPTransition(old, next *HTTPHold, action string) error {
	if old == nil {
		if next == nil {
			return nil
		}
		if action != "http_hold_intent" || next.State != "preparing" || next.Reservation != nil {
			return store.ErrCorrupt
		}
		for _, item := range next.Items {
			if item.State != "pending" || item.SHA != (domain.Hash{}) {
				return store.ErrCorrupt
			}
		}
		return nil
	}
	if next == nil || old.Unbound != next.Unbound || old.Site != next.Site || old.Captured != next.Captured || len(old.Items) != len(next.Items) {
		return store.ErrCorrupt
	}
	if e := validateHTTPReleaseTransition(old, next, action); e != nil {
		return e
	}
	if action != "http_hold_reserved" && action != "extend_complete" && action != "extend_intent" {
		left, _ := json.Marshal(old.Reservation)
		right, _ := json.Marshal(next.Reservation)
		if string(left) != string(right) {
			return store.ErrCorrupt
		}
	}
	left, _ := json.Marshal(old)
	right, _ := json.Marshal(next)
	if string(left) == string(right) {
		return nil
	}
	if action == "cleanup" {
		if next.State != "removed" {
			return store.ErrCorrupt
		}
	} else if action == "http_hold_released" {
		if old.State != next.State || !slices.Equal(old.Items, next.Items) {
			return store.ErrCorrupt
		}
	} else if action == "http_hold_reserved" || action == "extend_complete" || action == "extend_intent" {
		if old.State != next.State || old.Reservation != nil && next.Reservation == nil {
			return store.ErrCorrupt
		}
		if !slices.Equal(old.Items, next.Items) {
			return store.ErrCorrupt
		}
		if old.Reservation != nil && (next.Reservation.Sequence <= old.Reservation.Sequence || next.Reservation.Binding.Revision < old.Reservation.Binding.Revision || next.Reservation.Binding.Until < old.Reservation.Binding.Until) {
			return store.ErrCorrupt
		}
	} else if action != "http_hold_complete" || old.State != "preparing" && old.State != "partial" || next.State != "active" && next.State != "partial" {
		return store.ErrCorrupt
	}
	for i, item := range old.Items {
		n := next.Items[i]
		if item.Record != n.Record || item.Source != n.Source || item.Expires != n.Expires || item.State == "removed" && n.State != "removed" || item.State == "held" && (n.State != "held" && n.State != "removed" || item.SHA != n.SHA) {
			return store.ErrCorrupt
		}
	}
	return nil
}

func (s *Store) httpPath(id, record domain.ID) string {
	return filepath.Join(s.artifactDir(id, "http"), record.String()+".json")
}

// httpOperations は既に保全済みの受理投稿に限ってHTTP原本の対応を許可する。
func (s *Store) httpOperations(c Case, now time.Time) (map[domain.ID]bool, error) {
	if c.HTTP != nil && c.HTTP.Unbound {
		return map[domain.ID]bool{}, nil
	}
	rows, e := s.Records(c, now)
	if e != nil {
		return nil, e
	}
	ops := map[domain.ID]bool{}
	for _, r := range rows {
		ops[r.Operation] = true
	}
	return ops, nil
}

// verifyHTTP は元署名と、案件板・期間・保全済み操作の対応を検査する。
func (s *Store) verifyHTTP(c Case, site domain.ID, entry evidence.Entry, ops map[domain.ID]bool) (evidence.OptionalEvidence, error) {
	r, e := evidence.VerifyOptionalEntry(entry, site, s.key.Public().(ed25519.PublicKey))
	if e != nil {
		return r, e
	}
	v := r.Record
	if !httpRecordMatches(c, v, ops) {
		return r, ErrInvalid
	}
	return r, nil
}

// HoldHTTP は独立した固定intentを先行保存してから案件コピーを作る。原本期限は変更しない。
// 呼出元は現在の担当・追加権限・再認証とreader41を確定し、Storeの排他を保持する。
func (s *Store) HoldHTTP(id, actor domain.ID, etag, key, purpose string, site domain.ID, entries []evidence.Entry, now time.Time) (Case, error) {
	return s.holdHTTP(id, actor, etag, key, purpose, site, entries, now, false)
}

// holdHTTP は固定した種別で既存のコピー処理を実行する。
func (s *Store) holdHTTP(id, actor domain.ID, etag, key, purpose string, site domain.ID, entries []evidence.Entry, now time.Time, unbound bool) (Case, error) {
	c, e := s.prepareHTTPHold(id, actor, etag, key, purpose, site, entries, now, unbound)
	if e != nil {
		return c, e
	}
	if c.HTTP.State == "active" {
		return c, nil
	}
	if c.HTTP.Reservation != nil {
		return c, ErrConflict
	}
	ops, e := s.httpOperations(c, now)
	if e != nil {
		return c, e
	}
	return s.resumeHTTPHold(c, actor, entries, ops, now, nil, nil)
}

// PrepareHTTPHold は固定集合intentだけを保存し、元所有列を待つ前に案件排他を解放できるようにする。
func (s *Store) PrepareHTTPHold(id, actor domain.ID, etag, key, purpose string, site domain.ID, entries []evidence.Entry, now time.Time) (Case, error) {
	return s.prepareHTTPHold(id, actor, etag, key, purpose, site, entries, now, false)
}

// prepareHTTPHold は明示した保全種別を固定intentへ束縛する。
func (s *Store) prepareHTTPHold(id, actor domain.ID, etag, key, purpose string, site domain.ID, entries []evidence.Entry, now time.Time, unbound bool) (Case, error) {
	if len(entries) > evidence.MaxOptionalQueryRecords {
		return Case{}, ErrLimit
	}
	input := struct {
		Purpose string    `json:"purpose"`
		Site    domain.ID `json:"site_id"`
		Unbound bool      `json:"unbound_http"`
	}{purpose, site, unbound}
	c, replay, e := s.Replay(id, actor, "http_hold_intent", etag, key, input)
	if e != nil {
		return c, e
	}
	if replay {
		c, e = s.Get(id)
		if e != nil {
			return c, e
		}
		etag = c.ETag()
	}
	c, e = s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.Extension != nil && c.Extension.State == "pending" {
		return c, ErrConflict
	}
	if !validHTTPHoldStart(c, unbound) || site == (domain.ID{}) {
		return c, ErrConflict
	}
	if replay && c.HTTP != nil && c.HTTP.State == "active" {
		_, e := s.HTTPRecords(c, now)
		return c, e
	}
	if c.HTTP != nil && (c.HTTP.Site != site || c.HTTP.State != "preparing" && c.HTTP.State != "partial") {
		return c, ErrConflict
	}
	if e = s.requireCapacity(evidence.MaxOptionalQueryBytes); e != nil {
		return c, e
	}
	ops := map[domain.ID]bool{}
	if !unbound {
		ops, e = s.httpOperations(c, now)
		if e != nil {
			return c, e
		}
	}
	if c.HTTP == nil {
		if len(entries) > evidence.MaxOptionalQueryRecords {
			return c, ErrLimit
		}
		h := &HTTPHold{Unbound: unbound, Site: site, Captured: domain.Time(now.UnixNano()), State: "preparing", Items: []Item{}}
		if unbound {
			c.HTTP = h
		}
		seen := map[domain.ID]bool{}
		total := 0
		for _, entry := range entries {
			r, err := s.verifyHTTP(c, site, entry, ops)
			if err != nil {
				return c, err
			}
			if seen[r.Record.ID] {
				return c, ErrInvalid
			}
			seen[r.Record.ID] = true
			if r.Record.Until <= max(h.Captured, domain.Time(time.Now().UnixNano())) {
				return c, ErrExpired
			}
			raw, err := json.Marshal(entry.Event)
			if err != nil {
				return c, err
			}
			total += len(raw)
			if total > evidence.MaxOptionalQueryBytes {
				return c, ErrLimit
			}
			h.Items = append(h.Items, Item{Record: r.Record.ID, Source: r.SourceSHA, Expires: r.Record.Until, State: "pending"})
		}
		c.HTTP = h
	}
	if !replay {
		if unbound {
			c.State = "preparing"
		}
		c, e = s.append(c, actor, "http_hold_intent", purpose, nil, etag, key, input, now)
		if e != nil {
			return c, e
		}
		if e = s.after("http_hold:intent"); e != nil {
			return c, e
		}
	}
	return c, nil
}

// HTTPSourceIDs は再開に必要な未コピー・期限内の固定原本IDだけを返す。
// 耐久コピーがあれば原本列を照会せず再開できる。保全済みコピーの欠落は補完せず拒否する。
func (s *Store) HTTPSourceIDs(c Case, now time.Time) ([]domain.ID, error) {
	current, e := s.AuthorizeState(c.ID, c.ETag(), now)
	if e != nil {
		return nil, e
	}
	c = current
	if c.HTTP == nil {
		return nil, ErrInvalid
	}
	ops, e := s.httpOperations(c, now)
	if e != nil {
		return nil, e
	}
	ids := []domain.ID{}
	for _, item := range c.HTTP.Items {
		raw, e := readArtifact(s.httpPath(c.ID, item.Record))
		if os.IsNotExist(e) {
			if item.State == "held" {
				return nil, store.ErrCorrupt
			}
			if item.Expires > max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano())) {
				ids = append(ids, item.Record)
			}
			continue
		}
		if e != nil {
			return nil, e
		}
		if item.State == "held" && sha256.Sum256(raw) != item.SHA {
			return nil, store.ErrCorrupt
		}
		entry, e := decodeHTTPArtifact(raw)
		if e != nil {
			return nil, e
		}
		r, e := s.verifyHTTP(c, c.HTTP.Site, entry, ops)
		if e != nil || r.Record.ID != item.Record || r.SourceSHA != item.Source || r.Record.Until != item.Expires {
			return nil, store.ErrCorrupt
		}
	}
	return ids, nil
}

// resumeHTTPHold は既存コピーを先に照合し、原本が満了しても耐久コピーを取り直さない。
func (s *Store) resumeHTTPHold(c Case, actor domain.ID, entries []evidence.Entry, ops map[domain.ID]bool, now time.Time, lease *evidence.OptionalHoldReceipt, check func() error) (Case, error) {
	if c.Extension != nil && c.Extension.State == "pending" {
		return c, ErrConflict
	}
	if e := prepareDir(s.artifactDir(c.ID, "http")); e != nil {
		return c, e
	}
	available := map[domain.ID]evidence.Entry{}
	for _, entry := range entries {
		available[entry.Event.RecordID] = entry
	}
	c.HTTP.State = "active"
	total := 0
	for i, item := range c.HTTP.Items {
		if check != nil {
			if e := check(); e != nil {
				return c, e
			}
		}
		if lease != nil && max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano())) >= lease.Binding.Until {
			return c, ErrExpired
		}
		raw, e := readArtifact(s.httpPath(c.ID, item.Record))
		fresh := os.IsNotExist(e)
		if fresh {
			entry, found := available[item.Record]
			if !found && lease != nil {
				return c, store.ErrIncomplete
			}
			if !found || lease == nil && item.Expires <= max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano())) {
				if item.State == "held" {
					return c, store.ErrCorrupt
				}
				c.HTTP.Items[i].State, c.HTTP.State = "missing", "partial"
				continue
			}
			raw, e = json.Marshal(entry.Event)
		}
		if e != nil {
			return c, e
		}
		total += len(raw)
		if total > evidence.MaxOptionalQueryBytes {
			return c, ErrLimit
		}
		entry, err := decodeHTTPArtifact(raw)
		if err != nil {
			return c, err
		}
		r, e := s.verifyHTTP(c, c.HTTP.Site, entry, ops)
		if e != nil || r.Record.ID != item.Record || r.SourceSHA != item.Source || r.Record.Until != item.Expires {
			return c, store.ErrCorrupt
		}
		digest := sha256.Sum256(raw)
		if item.State == "held" && item.SHA != digest {
			return c, store.ErrCorrupt
		}
		if fresh {
			if lease == nil && item.Expires <= max(domain.Time(now.UnixNano()), domain.Time(time.Now().UnixNano())) {
				c.HTTP.Items[i].State, c.HTTP.State = "missing", "partial"
				continue
			}
			if e = writeArtifact(s.httpPath(c.ID, item.Record), raw); e != nil {
				return c, e
			}
			if e = s.after("http_hold:file"); e != nil {
				return c, e
			}
		}
		c.HTTP.Items[i].SHA, c.HTTP.Items[i].State = digest, "held"
	}
	if check != nil {
		if e := check(); e != nil {
			return c, e
		}
	}
	if domain.Time(time.Now().UnixNano()) >= c.Until {
		return c, ErrExpired
	}
	if c.HTTP.Unbound {
		c.State = c.HTTP.State
	}
	return s.append(c, actor, "http_hold_complete", "http_hold_copy", nil, "", "", nil, now)
}

// HTTPRecords は案件期限内のコピーを元署名と台帳hashで照合する。元7日期限は適用しない。
func (s *Store) HTTPRecords(c Case, now time.Time) ([]evidence.OptionalEvidence, error) {
	current, e := s.Get(c.ID)
	if e != nil {
		return nil, e
	}
	if current.Revision != c.Revision {
		return nil, ErrRevision
	}
	if _, e = s.AuthorizeState(c.ID, c.ETag(), now); e != nil {
		return nil, e
	}
	if c.HTTP == nil {
		return []evidence.OptionalEvidence{}, nil
	}
	if c.HTTP.State != "active" && c.HTTP.State != "partial" {
		return nil, ErrConflict
	}
	ops, e := s.httpOperations(c, now)
	if e != nil {
		return nil, e
	}
	return s.readHTTPRecords(c, ops)
}

// readHTTPRecords は期限判定済み、または停止検査用のコピーを元sourceまで照合する。
func (s *Store) readHTTPRecords(c Case, ops map[domain.ID]bool) ([]evidence.OptionalEvidence, error) {
	rows := []evidence.OptionalEvidence{}
	total := 0
	for _, item := range c.HTTP.Items {
		if item.State != "held" {
			continue
		}
		raw, e := readArtifact(s.httpPath(c.ID, item.Record))
		if e != nil {
			return nil, e
		}
		total += len(raw)
		if total > evidence.MaxOptionalQueryBytes {
			return nil, ErrLimit
		}
		if sha256.Sum256(raw) != item.SHA {
			return nil, store.ErrCorrupt
		}
		entry, err := decodeHTTPArtifact(raw)
		if err != nil {
			return nil, err
		}
		r, e := s.verifyHTTP(c, c.HTTP.Site, entry, ops)
		if e != nil || r.Record.ID != item.Record || r.SourceSHA != item.Source || r.Record.Until != item.Expires {
			return nil, store.ErrCorrupt
		}
		rows = append(rows, r)
	}
	return rows, nil
}

// projectHTTP は保全済み部分観測だけを受理操作へ結び、生payload/署名を提出列へ含めない。
func (s *Store) projectHTTP(c Case, rows []map[string]any, now time.Time) error {
	if c.HTTP == nil {
		return nil
	}
	logs, e := s.HTTPRecords(c, now)
	if e != nil {
		return e
	}
	missing := []domain.ID{}
	for _, item := range c.HTTP.Items {
		if item.State != "held" {
			missing = append(missing, item.Record)
		}
	}
	byOperation := map[domain.ID]map[string]any{}
	for _, row := range rows {
		id, ok := row["operation_id"].(domain.ID)
		if !ok {
			return store.ErrCorrupt
		}
		byOperation[id] = row
		row["optional_http"] = []evidence.OptionalEvidence{}
		row["optional_http_completeness"] = "partial_observation"
		row["optional_http_hold_until_ns"] = c.Until
		row["optional_http_hold_state"] = c.HTTP.State
		row["optional_http_missing_ids"] = missing
	}
	for _, log := range logs {
		row := byOperation[*log.Record.Operation]
		if row == nil {
			return store.ErrCorrupt
		}
		row["optional_http"] = append(row["optional_http"].([]evidence.OptionalEvidence), log)
	}
	for _, row := range rows {
		app.AttachAcceptedHTTPResponse(row)
	}
	return nil
}

// decodeHTTPArtifact はbase64の元payloadを復元し、RawMessageの再整形による署名不一致を避ける。
func decodeHTTPArtifact(raw []byte) (evidence.Entry, error) {
	var event evidence.Event
	if strictjson.Decode(raw, &event) != nil || len(event.Payload) > ((evidence.MaxOptionalRecordBytes+(1<<10)+2)/3)*4 {
		return evidence.Entry{}, store.ErrCorrupt
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(event.Payload)
	if e != nil {
		return evidence.Entry{}, store.ErrCorrupt
	}
	return evidence.Entry{Event: event, Payload: payload}, nil
}
