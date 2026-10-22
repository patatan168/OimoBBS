// 非必須記録の期限回収を本文なし署名tombstone・snapshot・旧世代回収へ接続する。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// OptionalPayload はHTTP記録を日別kind8の元sourceへ結ぶ。必須投稿captureの型ではない。
type OptionalPayload struct {
	Owner  domain.ID      `json:"source_owner_id"`
	Day    domain.U64     `json:"source_subkey"`
	Seq    domain.U64     `json:"source_control_seq"`
	Record OptionalRecord `json:"record"`
}

type optionalRemoved struct {
	Seq      domain.U64  `json:"source_control_seq"`
	Envelope Event       `json:"envelope_without_payload"`
	Until    domain.Time `json:"retention_until_ns"`
}
type optionalTombstone struct {
	Owner   domain.ID         `json:"source_owner_id"`
	Day     domain.U64        `json:"source_subkey"`
	Seq     domain.U64        `json:"source_control_seq"`
	At      domain.Time       `json:"removed_at_ns"`
	Reason  string            `json:"reason"`
	Removed []optionalRemoved `json:"removed"`
}

func optionalKind(kind string) bool {
	return kind == "attempt" || kind == "response" || kind == "receipt"
}

// ValidateOptionalPayload は非必須記録だけを署名対象として検証する。
func ValidateOptionalPayload(kind string, raw []byte) error {
	var p OptionalPayload
	if !optionalKind(kind) || strictjson.Decode(raw, &p) != nil || p.Seq == 0 {
		return store.ErrCorrupt
	}
	want := p.Record.Kind
	if want == "access" {
		want = "receipt"
	}
	if kind != want {
		return store.ErrCorrupt
	}
	return p.Record.Validate()
}

// validatePayload は本文なし回収証跡だけをjournal共通で検査し、通常payloadは所有者へ渡す。
func (j *Journal) validatePayload(kind string, raw []byte) error {
	if kind == "journal_checkpoint" {
		_, e := DecodeJournalCheckpoint(raw)
		return e
	}
	if kind == "tombstone" {
		return j.validateTombstone(raw)
	}
	return j.validate(kind, raw)
}

func (j *Journal) decodeOptionalTombstone(raw []byte) (optionalTombstone, error) {
	var t optionalTombstone
	if strictjson.Decode(raw, &t) != nil || t.Owner != j.owner || uint64(t.Day) != j.day || t.Seq == 0 || t.At <= 0 || t.Reason != "optional_retention_expired" || len(t.Removed) == 0 || len(t.Removed) > 128 {
		return t, store.ErrCorrupt
	}
	seen := map[domain.ID]bool{}
	for _, r := range t.Removed {
		e := r.Envelope
		if r.Seq == 0 || r.Seq >= t.Seq || r.Until <= 0 || r.Until > t.At || e.Payload != "" || e.Schema != "evidence-v1" || !optionalKind(e.Kind) || e.RecordID == (domain.ID{}) || e.SigningKeyID != j.keyID || seen[e.RecordID] {
			return t, store.ErrCorrupt
		}
		seen[e.RecordID] = true
		if digest(Source{j.owner, j.day, uint64(r.Seq)}, e.RecordID, e.Kind, e.PayloadSHA, e.PreviousSHA) != e.EventSHA {
			return t, store.ErrCorrupt
		}
		signature, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
		if err != nil || base64.StdEncoding.EncodeToString(signature) != e.Signature || !ed25519.Verify(j.key.Public().(ed25519.PublicKey), e.EventSHA[:], signature) {
			return t, store.ErrCorrupt
		}
	}
	return t, nil
}

// addOptionalRemoved は回収証跡から元のseq/hash連鎖だけを復元し、本文を補完しない。
func (j *Journal) addOptionalRemoved(chain map[uint64]Event, raw []byte) error {
	t, e := j.decodeOptionalTombstone(raw)
	if e != nil {
		return e
	}
	for _, r := range t.Removed {
		if _, exists := chain[uint64(r.Seq)]; exists || j.ids[r.Envelope.RecordID] {
			return store.ErrCorrupt
		}
		chain[uint64(r.Seq)] = r.Envelope
		j.ids[r.Envelope.RecordID] = true
	}
	return nil
}

// validateOptionalRemoval は非必須の保存済み完全型だけの除去を許す。欠番の署名証跡はreplayで照合する。
func validateOptionalRemoval(kind, key string, old json.RawMessage) error {
	var event Event
	if !optionalKind(kind) || strictjson.Decode(old, &event) != nil || event.RecordID.String() != key || event.Kind != kind {
		return store.ErrCorrupt
	}
	raw, e := decodePayload(event)
	if e != nil {
		return e
	}
	return ValidateOptionalPayload(kind, raw)
}

// PruneOptional は最大128件の満了行を先行証跡付きで除去し、全旧世代の元bytesを回収する。
// 通常投稿のproposal/decisionは対象外。停止時は同じsnapshot intentをOpenで再開する。
func (j *Journal) PruneOptional(now domain.Time, boundary func(string) error) (int, error) {
	if j.stopped || now <= 0 {
		return 0, store.ErrCorrupt
	}
	if boundary == nil {
		boundary = func(string) error { return nil }
	}
	if e := j.resumeOptionalPrune(); e != nil {
		return 0, e
	}
	if j.log == nil {
		return 0, nil
	}
	return j.pruneOptionalBatch(now, boundary, true)
}

// pruneOptionalBatch は128行までを一つの署名frameで確定する。bulk時は最後にまとめて再検証する。
func (j *Journal) pruneOptionalBatch(now domain.Time, boundary func(string) error, compact bool) (int, error) {
	t := optionalTombstone{Owner: j.owner, Day: domain.U64(j.day), Seq: domain.U64(j.seq + 1), At: now, Reason: "optional_retention_expired", Removed: []optionalRemoved{}}
	changes := []store.Mutation{}
	for _, entry := range j.entries {
		if !optionalKind(entry.Event.Kind) {
			continue
		}
		var p OptionalPayload
		if strictjson.Decode(entry.Payload, &p) != nil {
			return 0, store.ErrCorrupt
		}
		if p.Record.Until > now || j.optionalHeld(p.Record.ID, now) {
			continue
		}
		event := entry.Event
		event.Payload = ""
		t.Removed = append(t.Removed, optionalRemoved{p.Seq, event, p.Record.Until})
		changes = append(changes, store.Mutation{Collection: event.Kind, Key: event.RecordID.String(), ExpectedRevision: p.Seq, Value: json.RawMessage("null")})
		if len(t.Removed) == 128 {
			break
		}
	}
	if len(t.Removed) == 0 {
		return 0, nil
	}
	raw, e := json.Marshal(t)
	if e != nil {
		return 0, e
	}
	previous := j.entries[len(j.entries)-1].Event.EventSHA
	id := domain.NewID()
	event, e := Seal(Source{j.owner, j.day, j.seq + 1}, id, "tombstone", raw, previous, j.keyID, j.key)
	if e != nil {
		return 0, e
	}
	value, e := json.Marshal(event)
	if e != nil {
		return 0, e
	}
	changes = append(changes, store.Mutation{Collection: "tombstone", Key: id.String(), Value: value})
	op := store.ControlOperation{Schema: 1, Seq: t.Seq, ExpectedSeq: domain.U64(j.seq), Committed: now, Actor: domain.Actor{Kind: "system", Reason: "optional_retention_expired"}, Mutations: changes, Result: store.ControlResult{Code: "optional_retention_expired", Targets: []string{}}}
	opRaw, e := json.Marshal(op)
	if e != nil {
		return 0, e
	}
	frame, e := store.EncodeFrame(store.Frame{FirstSeq: j.seq + 1, Records: []store.Record{{ID: id, JSON: opRaw}}})
	if e != nil {
		return 0, e
	}
	j.optionalReclaimPending = true
	result := j.log.Append(frame)
	if result.Status != store.Durable {
		if result.Status == store.Unknown {
			j.stopped = true
		}
		return 0, result.Err
	}
	// Sync済みframeの選択集合だけをメモリへ反映し、元IDを再使用可能にしない。
	removed := map[domain.ID]bool{}
	for _, r := range t.Removed {
		removed[r.Envelope.RecordID] = true
	}
	retained := j.entries[:0]
	for _, entry := range j.entries {
		if !removed[entry.Event.RecordID] {
			retained = append(retained, entry)
		}
	}
	clear(j.entries[len(retained):])
	j.entries = append(retained, Entry{event, bytes.Clone(raw)})
	j.entryIndex = nil
	j.ids[id] = true
	j.seq++
	if compact {
		if e = j.replay(); e != nil {
			j.stopped = true
			return len(t.Removed), e
		}
	}
	if e = boundary("optional:removed"); e != nil {
		j.stopped = true
		return len(t.Removed), e
	}
	if compact {
		if e = j.compactOptional(boundary); e != nil {
			j.stopped = true
			return len(t.Removed), e
		}
	}
	if compact {
		j.optionalReclaimPending = false
	}
	return len(t.Removed), nil
}

// PruneOptionalAll は全満了行を128行の署名frameへ分割し、最後に一度だけsnapshotを切り替える。
// 同じ所有列の中で実行し、途中停止は確定済みtombstoneから起動時に再開する。
func (j *Journal) PruneOptionalAll(now domain.Time, boundary func(string) error) (int, error) {
	if j.stopped || now <= 0 {
		return 0, store.ErrCorrupt
	}
	if boundary == nil {
		boundary = func(string) error { return nil }
	}
	if e := j.resumeOptionalPrune(); e != nil {
		return 0, e
	}
	if j.log == nil {
		return 0, nil
	}
	removed := 0
	for {
		n, e := j.pruneOptionalBatch(now, boundary, false)
		removed += n
		if e != nil {
			return removed, e
		}
		if n == 0 {
			break
		}
	}
	if removed == 0 {
		return 0, nil
	}
	if e := j.replay(); e != nil {
		j.stopped = true
		return removed, e
	}
	if e := j.compactOptional(boundary); e != nil {
		j.stopped = true
		return removed, e
	}
	j.optionalReclaimPending = false
	return removed, nil
}

// compactOptional は署名検証済み全現在行の同一snapshotを先行保存してから切り替える。
func (j *Journal) compactOptional(boundary func(string) error) error {
	h := j.log.HistoryHeader()
	h.Generation++
	h.BaseSeq = j.seq
	raw, e := store.EncodeControlSnapshot(h, j.log.State(), 6, j.validateValue)
	if e != nil {
		return e
	}
	path := filepath.Join(j.dir, ".optional-prune.snapshot")
	if e = writeOptionalIntent(path, raw); e != nil {
		return e
	}
	if e = boundary("optional:snapshot_intent"); e != nil {
		return e
	}
	result := j.log.ResumeSnapshot(raw)
	if result.Status != store.Durable {
		j.stopped = true
		return result.Err
	}
	if e = boundary("optional:snapshot_current"); e != nil {
		return e
	}
	return j.finishOptionalPrune(path)
}

// resumeOptionalPrune は既存状態との完全一致だけを再開する。元bytesを含む旧世代を先に削除しない。
func (j *Journal) resumeOptionalPrune() error {
	if j.log == nil {
		return nil
	}
	path := filepath.Join(j.dir, ".optional-prune.snapshot")
	info, e := os.Lstat(path)
	if os.IsNotExist(e) {
		// intent前の停止では現在stateのtombstoneから安全に再生成できる。
		if j.log.HistoryHeader().BaseSeq < uint64(j.log.State().Seq) {
			for _, entry := range j.entries {
				if entry.Event.Kind == "tombstone" && entrySeq(entry.Payload) > j.log.HistoryHeader().BaseSeq {
					return j.compactOptional(func(string) error { return nil })
				}
			}
		}
		return nil
	}
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 64<<20 {
		return store.ErrCorrupt
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	if len(raw) < 64 {
		h := j.log.HistoryHeader()
		h.Generation++
		h.BaseSeq = j.seq
		want, err := store.EncodeControlSnapshot(h, j.log.State(), 6, j.validateValue)
		if err != nil {
			return err
		}
		if err = completeOptionalIntent(path, raw, want); err != nil {
			return err
		}
		raw = want
	} else if _, ok := j.log.SnapshotIdentity(); !ok || j.log.HistoryHeader().BaseSeq < j.seq {
		h := j.log.HistoryHeader()
		h.Generation++
		h.BaseSeq = j.seq
		want, err := store.EncodeControlSnapshot(h, j.log.State(), 6, j.validateValue)
		if err != nil {
			return err
		}
		if err = completeOptionalIntent(path, raw, want); err != nil {
			return err
		}
		raw = want
	}
	if snapshot, ok := j.log.SnapshotIdentity(); !ok || snapshot.SHA != sha256.Sum256(raw) {
		result := j.log.ResumeSnapshot(raw)
		if result.Status != store.Durable {
			j.stopped = true
			return result.Err
		}
	}
	return j.finishOptionalPrune(path)
}

var optionalControlName = regexp.MustCompile(`^control-([0-9]{6,20})\.(wal|snap)$`)

// finishOptionalPrune はcurrentの参照先を保持して旧世代だけを物理回収し、最後にintentを消す。
func (j *Journal) finishOptionalPrune(intent string) error {
	m, e := store.InspectControlManifest(j.dir)
	if e != nil {
		return e
	}
	entries, e := os.ReadDir(j.dir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "control.current" || name == m.Delta.File || m.Snapshot != nil && name == m.Snapshot.File || name == filepath.Base(intent) {
			continue
		}
		match := optionalControlName.FindStringSubmatch(name)
		if match == nil {
			return store.ErrCorrupt
		}
		generation, e := strconv.ParseUint(match[1], 10, 64)
		if e != nil || generation >= uint64(m.Generation) {
			return store.ErrCorrupt
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return store.ErrCorrupt
		}
		if e = os.Remove(filepath.Join(j.dir, name)); e != nil {
			return e
		}
	}
	if e = store.SyncDirectory(j.dir); e != nil {
		return e
	}
	if e = os.Remove(intent); e != nil {
		return e
	}
	return store.SyncDirectory(j.dir)
}

// writeOptionalIntent は同じ完成候補だけを再利用し、異なるprefix・未知候補を上書きしない。
func writeOptionalIntent(path string, raw []byte) error {
	if saved, e := os.ReadFile(path); e == nil {
		if bytes.Equal(saved, raw) {
			return nil
		}
		return store.ErrCorrupt
	} else if !os.IsNotExist(e) {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, writeErr := f.Write(raw)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	e = errors.Join(writeErr, f.Close())
	if e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}

// completeOptionalIntent は署名済み現在状態から再生成した候補の一致prefixだけを補完する。
func completeOptionalIntent(path string, saved, want []byte) error {
	if len(saved) > len(want) || !bytes.Equal(saved, want[:len(saved)]) {
		return store.ErrCorrupt
	}
	if len(saved) == len(want) {
		return nil
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if e != nil {
		return e
	}
	_, e = f.Write(want[len(saved):])
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(path))
}

func entrySeq(raw []byte) uint64 {
	var v struct {
		Seq domain.U64 `json:"source_control_seq"`
	}
	_ = json.Unmarshal(raw, &v)
	return uint64(v.Seq)
}
