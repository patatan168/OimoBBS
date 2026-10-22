// 保全コピーの同期確定・原本署名照合・期限更新・解除と停止点再開を提供する。
package disclosure

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"oimobbs/internal/app"
	"oimobbs/internal/domain"
	"oimobbs/internal/evidence"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"slices"
	"time"
)

func decode(v string) []byte { b, _ := base64.StdEncoding.Strict().DecodeString(v); return b }
func (s *Store) artifactDir(id domain.ID, kind string) string {
	return filepath.Join(s.root, id.String(), kind)
}
func (s *Store) itemPath(id, record domain.ID) string {
	return filepath.Join(s.artifactDir(id, "items"), record.String()+".json")
}
func prepareDir(path string) error {
	if e := os.Mkdir(path, 0700); e != nil && !os.IsExist(e) {
		return e
	}
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	return syncDir(filepath.Dir(path))
}
func writeArtifact(path string, raw []byte) error {
	if len(raw) > MaxArtifactBytes {
		return ErrLimit
	}
	if existing, e := readArtifact(path); e == nil {
		if !bytes.Equal(existing, raw) {
			return store.ErrCorrupt
		}
		return nil
	} else if !os.IsNotExist(e) {
		return e
	}
	temp := path + ".tmp"
	if e := os.Remove(temp); e != nil && !os.IsNotExist(e) {
		return e
	}
	f, e := os.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(raw)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(temp, path); e != nil {
		return e
	}
	return syncDir(filepath.Dir(path))
}
func readArtifact(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > MaxArtifactBytes {
		return nil, store.ErrCorrupt
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxArtifactBytes+1))
}

// Matches は固定案件範囲へ含まれる受理記録だけを選ぶ。
func Matches(scope Scope, r app.AcceptedEvidence) bool {
	return scope.Board == r.Board && (scope.Thread == 0 || scope.Thread == r.Thread) && r.Committed >= scope.From && r.Committed < scope.To && (len(scope.Records) == 0 || slices.Contains(scope.Records, r.RecordID))
}

// Hold は期限内の固定対象をintentへ保存してからコピーし、全成功時だけactiveへ進める。
func (s *Store) Hold(id, actor domain.ID, etag, key, purpose string, records []app.AcceptedEvidence, now time.Time) (Case, error) {
	c, e := s.PrepareHold(id, actor, etag, key, purpose, records, now)
	if e != nil {
		return c, e
	}
	if c.Required != nil {
		return c, ErrConflict
	}
	return s.resumeHold(c, actor, records, now)
}

// PrepareHold は期限内の固定対象を署名intentへ保存する。原本所有列を待つ前に案件排他を解放できる。
// 保全コピーを作らず、既存の同一intentでは対象を取り直さない。
func (s *Store) PrepareHold(id, actor domain.ID, etag, key, purpose string, records []app.AcceptedEvidence, now time.Time) (Case, error) {
	input := struct {
		Purpose string `json:"purpose"`
	}{purpose}
	if c, ok, e := s.Replay(id, actor, "hold_intent", etag, key, input); e != nil {
		return c, e
	} else if ok {
		return s.currentPreparedHold(c.ID)
	}
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if c.Rejected != nil || c.HTTP != nil && c.HTTP.Unbound {
		return c, ErrConflict
	}
	if requiredExtensionPending(c) {
		return c, ErrConflict
	}
	if c.State == "preparing" || c.State == "partial" {
		return s.append(c, actor, "hold_intent", purpose, nil, etag, key, input, now)
	}
	return s.prepareNewHold(c, actor, etag, key, purpose, input, records, now)
}

// prepareNewHold は固定集合を署名し、コピー前の再開停止点を設ける。
func (s *Store) prepareNewHold(c Case, actor domain.ID, etag, key, purpose string, input any, records []app.AcceptedEvidence, now time.Time) (Case, error) {
	if c.State != "draft" {
		return c, ErrConflict
	}
	if e := s.requireCapacity(MaxArtifactBytes); e != nil {
		return c, e
	}
	items, e := selectedHoldItems(c.Scope, records, now)
	if e != nil {
		return c, e
	}
	c.Items, c.State = items, "preparing"
	c, e = s.append(c, actor, "hold_intent", purpose, nil, etag, key, input, now)
	if e != nil {
		return c, e
	}
	return c, s.after("hold:intent")
}

// selectedHoldItems は期限内の固定対象だけを本文なしintentへ投影する。
func selectedHoldItems(scope Scope, records []app.AcceptedEvidence, now time.Time) ([]Item, error) {
	items := []Item{}
	for _, r := range records {
		if Matches(scope, r) && r.Expires > domain.Time(now.UnixNano()) {
			items = append(items, Item{Record: r.RecordID, Source: r.Proposal.Event.EventSHA, Expires: r.Expires, State: "pending"})
		}
	}
	if len(items) == 0 || len(items) > MaxRecords {
		return nil, ErrLimit
	}
	if len(scope.Records) > 0 && len(items) != len(scope.Records) {
		return nil, ErrExpired
	}
	return items, nil
}

// currentPreparedHold は再送の履歴行から現在状態へ進め、取消済みの古いintentを返さない。
func (s *Store) currentPreparedHold(id domain.ID) (Case, error) {
	c, e := s.Get(id)
	if e != nil {
		return c, e
	}
	if c.State != "preparing" && c.State != "partial" && c.State != "active" {
		return c, ErrExpired
	}
	return c, nil
}

// resumeHold は従来保全の署名/copy再開経路。耐久元予約付き経路は別に現在予約を照合する。
func (s *Store) resumeHold(c Case, actor domain.ID, records []app.AcceptedEvidence, now time.Time) (Case, error) {
	return s.resumeHoldChecked(c, actor, records, now, nil)
}

// resumeHoldChecked は元予約の再照合と現在案件CAS検査を各copy/完了の前に行う内部経路。
func (s *Store) resumeHoldChecked(c Case, actor domain.ID, records []app.AcceptedEvidence, now time.Time, check func() error) (Case, error) {
	current, e := s.Get(c.ID)
	if e != nil {
		return current, e
	}
	if current.Required != nil && check == nil {
		return current, ErrInvalid
	}
	if current.State == "active" {
		return current, nil
	}
	c = current
	if e = s.beginRequiredHoldCopy(c, now, check); e != nil {
		return c, e
	}
	c, e = s.copyRequiredHoldItems(c, availableHoldRecords(c.Scope, records), now, check)
	if e != nil {
		return c, e
	}
	if e = s.checkRequiredCopyGuard(c.ID, c.Revision, now, check); e != nil {
		return c, e
	}
	return s.append(c, actor, "hold_complete", "hold_copy", nil, "", "", nil, now)
}

// beginRequiredHoldCopy は現在状態/期限と元予約を照合してから私有copy領域を準備する。
func (s *Store) beginRequiredHoldCopy(c Case, now time.Time, check func() error) error {
	if c.State != "preparing" && c.State != "partial" || domain.Time(now.UnixNano()) >= c.Until {
		return ErrExpired
	}
	if e := s.checkRequiredCopyGuard(c.ID, c.Revision, now, check); e != nil {
		return e
	}
	return prepareDir(s.artifactDir(c.ID, "items"))
}

// availableHoldRecords は案件外の原本で固定対象を上書きしないよう範囲を再照合する。
func availableHoldRecords(scope Scope, records []app.AcceptedEvidence) map[domain.ID]app.AcceptedEvidence {
	available := map[domain.ID]app.AcceptedEvidence{}
	for _, r := range records {
		if Matches(scope, r) {
			available[r.RecordID] = r
		}
	}
	return available
}

// copyRequiredHoldItems は元予約を各copy直前に照合し、署名検証済みbytesだけを同期保存する。
func (s *Store) copyRequiredHoldItems(c Case, available map[domain.ID]app.AcceptedEvidence, now time.Time, check func() error) (Case, error) {
	total := 0
	c.State = "active"
	for i, item := range c.Items {
		r, ok := available[item.Record]
		if !ok || r.Proposal.Event.EventSHA != item.Source {
			c.Items[i].State = "missing"
			c.State = "partial"
			continue
		}
		raw, err := json.Marshal(r)
		if err != nil {
			return c, err
		}
		total += len(raw)
		if total > MaxArtifactBytes {
			return c, ErrLimit
		}
		if err = s.verifyHeldCaseRecord(c, r); err != nil {
			return c, err
		}
		if err = s.checkRequiredCopyGuard(c.ID, c.Revision, now, check); err != nil {
			return c, err
		}
		if err = writeArtifact(s.itemPath(c.ID, item.Record), raw); err != nil {
			return c, err
		}
		c.Items[i].SHA = sha256.Sum256(raw)
		c.Items[i].State = "held"
	}
	return c, nil
}

// checkRequiredCopyGuard は案件排他を解放する元待ちcallbackの後に現在CAS/期限を再確認する。
func (s *Store) checkRequiredCopyGuard(id domain.ID, revision domain.U64, now time.Time, check func() error) error {
	if check == nil {
		return nil
	}
	if e := check(); e != nil {
		return e
	}
	c, e := s.Get(id)
	if e != nil {
		return e
	}
	if c.Revision != revision || c.State != "preparing" && c.State != "partial" {
		return ErrConflict
	}
	if domain.Time(now.UnixNano()) >= c.Until {
		return ErrExpired
	}
	return nil
}
func (s *Store) verifyRecord(r app.AcceptedEvidence) error {
	for _, entry := range []evidence.Entry{r.Proposal, r.Decision} {
		var src struct {
			Owner domain.ID  `json:"source_owner_id"`
			Day   domain.U64 `json:"source_subkey"`
			Seq   domain.U64 `json:"source_control_seq"`
		}
		if json.Unmarshal(entry.Payload, &src) != nil || src.Owner != r.Board {
			return store.ErrCorrupt
		}
		raw, e := evidence.Verify(evidence.Source{Owner: src.Owner, Subkey: uint64(src.Day), Seq: uint64(src.Seq)}, entry.Event, entry.Event.PreviousSHA, 10, s.key.Public().(ed25519.PublicKey))
		if e != nil || !bytes.Equal(raw, entry.Payload) {
			return store.ErrCorrupt
		}
	}
	var p struct {
		Owner domain.ID   `json:"source_owner_id"`
		Key   domain.U64  `json:"thread_key"`
		Op    domain.ID   `json:"operation_id"`
		At    domain.Time `json:"committed_at_ns"`
		Until domain.Time `json:"retention_until_ns"`
	}
	var d struct {
		ID       domain.ID   `json:"proposal_id"`
		SHA      domain.Hash `json:"proposal_event_sha256"`
		Decision string      `json:"decision"`
		Op       domain.ID   `json:"operation_id"`
	}
	if json.Unmarshal(r.Proposal.Payload, &p) != nil || json.Unmarshal(r.Decision.Payload, &d) != nil || p.Owner != r.Board || p.Key != r.Thread || p.Op != r.Operation || p.At != r.Committed || p.Until != r.Expires || r.Proposal.Event.RecordID != r.RecordID || d.ID != r.RecordID || d.SHA != r.Proposal.Event.EventSHA || d.Op != r.Operation || d.Decision != "accepted" {
		return store.ErrCorrupt
	}
	return nil
}

// Records は期限内の保全コピーをhash/署名照合して返す。破損や欠落を空の成功にしない。
func (s *Store) Records(c Case, now time.Time) ([]app.AcceptedEvidence, error) {
	if c.Rejected != nil || c.HTTP != nil && c.HTTP.Unbound {
		return nil, ErrConflict
	}
	if c.State != "active" && c.State != "partial" || domain.Time(now.UnixNano()) >= c.Until {
		return nil, ErrExpired
	}
	return s.readHeldRecords(c)
}

// readHeldRecords は認可/期限の確認済み読取り、または署名metadataの物理copy検査だけで使う。
func (s *Store) readHeldRecords(c Case) ([]app.AcceptedEvidence, error) {
	out := []app.AcceptedEvidence{}
	total := 0
	for _, item := range c.Items {
		if item.State != "held" {
			continue
		}
		raw, e := readArtifact(s.itemPath(c.ID, item.Record))
		if e != nil {
			return nil, e
		}
		total += len(raw)
		if total > MaxArtifactBytes {
			return nil, ErrLimit
		}
		if sha256.Sum256(raw) != item.SHA {
			return nil, store.ErrCorrupt
		}
		var r app.AcceptedEvidence
		if err := strictjson.Decode(raw, &r); err != nil {
			return nil, fmt.Errorf("held record: %w", err)
		}
		if r.RecordID != item.Record || r.Proposal.Event.EventSHA != item.Source || s.verifyHeldCaseRecord(c, r) != nil || !Matches(c.Scope, r) {
			return nil, store.ErrCorrupt
		}
		out = append(out, r)
	}
	return out, nil
}

// Extend は失効前だけ最長180日の明示期限更新を確定する。既存提出物の期限は延長しない。
func (s *Store) Extend(id, actor domain.ID, etag, key, purpose string, until domain.Time, now time.Time) (Case, error) {
	input := struct {
		Purpose string      `json:"purpose"`
		Until   domain.Time `json:"hold_until_ns"`
	}{purpose, until}
	if c, ok, e := s.Replay(id, actor, "extend", etag, key, input); ok || e != nil {
		return c, e
	}
	c, e := s.AuthorizeState(id, etag, now)
	if e != nil {
		return c, e
	}
	if requiredExtensionPending(c) || c.Extension != nil && c.Extension.State == "pending" {
		return c, ErrConflict
	}
	at := domain.Time(now.UnixNano())
	if until <= c.Until || until > at+domain.Time(180*24*time.Hour) {
		return c, ErrInvalid
	}
	c.Until = until
	c.Review = until - domain.Time(7*24*time.Hour)
	return s.append(c, actor, "extend", purpose, nil, etag, key, input, now)
}

// Release はアクセス停止を先に同期保存し、コピー・生成物の物理回収を再開可能にする。
func (s *Store) Release(id, actor domain.ID, etag, key, purpose string, now time.Time) (Case, error) {
	input := struct {
		Purpose string `json:"purpose"`
	}{purpose}
	if c, ok, e := s.Replay(id, actor, "release", etag, key, input); e != nil {
		return c, e
	} else if ok {
		return s.clean(c, actor, now)
	}
	c, e := s.authorizeRequiredCancellation(id, etag, now)
	if e != nil {
		return c, e
	}
	c.State = "releasing"
	c.Closed = domain.Time(now.UnixNano())
	c, e = s.append(c, actor, "release", purpose, nil, etag, key, input, now)
	if e != nil {
		return c, e
	}
	return s.clean(c, actor, now)
}
func (s *Store) clean(c Case, actor domain.ID, now time.Time) (Case, error) {
	current, e := s.Get(c.ID)
	if e != nil {
		return c, e
	}
	c = current
	if c.State == "closed" {
		return c, nil
	}
	if c.State != "releasing" {
		return c, ErrConflict
	}
	terminal := c
	terminal.State = "closed"
	if e = s.checkCaseCleanup(terminal, now); e != nil {
		return c, e
	}
	if e = s.removeCaseArtifacts(c.ID); e != nil {
		return c, e
	}
	c.State = "closed"
	if c.Rejected != nil {
		c.Rejected.State = "removed"
		for i := range c.Rejected.Items {
			c.Rejected.Items[i].State = "removed"
		}
	}
	if c.HTTP != nil {
		c.HTTP.State = "removed"
		for i := range c.HTTP.Items {
			c.HTTP.Items[i].State = "removed"
		}
	}
	for i := range c.Items {
		c.Items[i].State = "removed"
	}
	for i := range c.Exports {
		c.Exports[i].State = "removed"
	}
	return s.append(c, actor, "cleanup", "physical_cleanup", nil, "", "", nil, now)
}

// removeCaseArtifacts は全copy/提出物を削除して案件ディレクトリの変更を同期する。
func (s *Store) removeCaseArtifacts(id domain.ID) error {
	for _, kind := range []string{"items", "exports", "http"} {
		if e := os.RemoveAll(s.artifactDir(id, kind)); e != nil {
			return e
		}
	}
	return syncDir(filepath.Join(s.root, id.String()))
}

// Sweep は満了と解除途中を回収する。時計逆行時はアクセス・回収を拒否する。
func (s *Store) Sweep(now time.Time) error {
	cases, e := s.Cases()
	if e != nil {
		return e
	}
	for _, c := range cases {
		if e = s.sweepCase(c, now); e != nil {
			return e
		}
	}
	return nil
}

// sweepCase は期限到達の署名を先に保存し、全copy回収または提出物の回収へ進む。
func (s *Store) sweepCase(c Case, now time.Time) error {
	last, e := s.lastAudit(c.ID)
	if e != nil {
		return e
	}
	at := domain.Time(now.UnixNano())
	if at < last.At {
		return ErrExpired
	}
	if c.State == "closed" {
		return nil
	}
	if caseNeedsExpiration(c, at) {
		c.State, c.Closed = "releasing", at
		c, e = s.append(c, c.Creator, "expire", "retention_expired", nil, "", "", nil, now)
		if e != nil {
			return e
		}
	}
	if c.State == "releasing" {
		_, e = s.clean(c, c.Creator, now)
		return e
	}
	return s.sweepCaseExports(c, now)
}

func caseNeedsExpiration(c Case, at domain.Time) bool {
	return c.State != "releasing" && (at >= c.RetentionUntil() || c.State == "draft" && at >= c.Created+domain.Time(7*24*time.Hour))
}

// sweepCaseExports は必要な署名枠を確保してから、満了した提出物だけを物理回収する。
func (s *Store) sweepCaseExports(c Case, now time.Time) error {
	next, expired := expiredCaseExports(c, domain.Time(now.UnixNano()))
	if len(expired) == 0 {
		return nil
	}
	action := s.exportCleanupAction(c)
	if e := s.checkCaseCleanupAction(next, action, now); e != nil {
		return e
	}
	for _, id := range expired {
		for _, path := range []string{s.exportPath(c.ID, id), s.exportPath(c.ID, id) + ".tmp"} {
			if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
				return e
			}
		}
	}
	if e := s.syncCaseExportRemoval(c.ID); e != nil {
		return e
	}
	_, e := s.append(next, c.Creator, action, "export_expired", nil, "", "", nil, now)
	return e
}

func expiredCaseExports(c Case, at domain.Time) (Case, []domain.ID) {
	c.Exports = slices.Clone(c.Exports)
	expired := []domain.ID{}
	for i, v := range c.Exports {
		if v.State != "removed" && at >= v.Until {
			c.Exports[i].State = "removed"
			expired = append(expired, v.ID)
		}
	}
	return c, expired
}

func (s *Store) syncCaseExportRemoval(id domain.ID) error {
	if e := syncDir(s.artifactDir(id, "exports")); e != nil {
		if !os.IsNotExist(e) {
			return e
		}
		return syncDir(filepath.Join(s.root, id.String()))
	}
	return nil
}

// hashArtifact は提出ZIPをRAMへ載せず、固定上限内で元bytesのhashを検査する。
func hashArtifact(path string) (domain.Hash, int64, error) {
	var digest domain.Hash
	info, e := os.Lstat(path)
	if e != nil {
		return digest, 0, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > MaxArtifactBytes {
		return digest, 0, store.ErrCorrupt
	}
	f, e := os.Open(path)
	if e != nil {
		return digest, 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, MaxArtifactBytes+1))
	if n > MaxArtifactBytes {
		return digest, n, ErrLimit
	}
	copy(digest[:], h.Sum(nil))
	return digest, n, e
}
