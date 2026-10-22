// 全件満了した日を本文なし署名checkpointへ置き換え、日別dirと回収作業を完了させる。
package evidence

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type optionalCheckpoint struct {
	Owner       domain.ID   `json:"source_owner_id"`
	Day         domain.U64  `json:"source_subkey"`
	Seq         domain.U64  `json:"source_control_seq"`
	TerminalSeq domain.U64  `json:"terminal_seq"`
	TerminalSHA domain.Hash `json:"terminal_event_sha256"`
	At          domain.Time `json:"retired_at_ns"`
	Until       domain.Time `json:"retention_until_ns"`
	Reason      string      `json:"reason"`
}

// retireOptionalDay は全行回収済みの日だけを先行checkpointへ結び、dirを物理削除する。
func (s *OptionalStore) retireOptionalDay(day uint64, now domain.Time) error {
	j := s.journals[day]
	if j == nil {
		return nil
	}
	path := filepath.Join(s.root, fmt.Sprintf("%d.checkpoint.json", day))
	if _, e := os.Lstat(path); e == nil {
		p, e := s.readOptionalCheckpoint(path, day)
		if e != nil {
			return e
		}
		return s.finishOptionalDay(day, p)
	} else if !os.IsNotExist(e) {
		return e
	}
	if j.log == nil {
		return nil
	}
	for _, entry := range j.entries {
		if entry.Event.Kind == "tombstone" {
			continue
		}
		var payload OptionalPayload
		if !optionalKind(entry.Event.Kind) || json.Unmarshal(entry.Payload, &payload) != nil || payload.Record.Until > now || j.optionalHeld(payload.Record.ID, now) {
			return nil
		}
	}
	last := j.entries[len(j.entries)-1].Event.EventSHA
	p := optionalCheckpoint{Owner: s.owner, Day: domain.U64(day), Seq: domain.U64(j.seq + 1), TerminalSeq: domain.U64(j.seq), TerminalSHA: last, At: now, Until: now + domain.Time(30*24*time.Hour), Reason: "optional_day_expired"}
	raw, e := json.Marshal(p)
	if e != nil {
		return e
	}
	event, e := Seal(Source{s.owner, day, uint64(p.Seq)}, domain.NewID(), "checkpoint", raw, last, 10, s.key)
	if e != nil {
		return e
	}
	value, e := json.Marshal(event)
	if e != nil {
		return e
	}
	if e = writeOptionalAtomicIntent(path, value); e != nil {
		return e
	}
	if e = s.after("optional:checkpoint_saved"); e != nil {
		return e
	}
	return s.finishOptionalDay(day, p)
}

func (s *OptionalStore) readOptionalCheckpoint(path string, day uint64) (optionalCheckpoint, error) {
	var p optionalCheckpoint
	info, e := os.Lstat(path)
	if e != nil {
		return p, e
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 16<<10 {
		return p, store.ErrCorrupt
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return p, e
	}
	var event Event
	if strictjson.Decode(raw, &event) != nil || event.Kind != "checkpoint" {
		return p, store.ErrCorrupt
	}
	decoded, e := decodePayload(event)
	if e != nil || strictjson.Decode(decoded, &p) != nil {
		return p, store.ErrCorrupt
	}
	if p.Owner != s.owner || uint64(p.Day) != day || p.TerminalSeq == 0 || p.Seq != p.TerminalSeq+1 || p.At <= 0 || p.Until != p.At+domain.Time(30*24*time.Hour) || p.Reason != "optional_day_expired" || event.PreviousSHA != p.TerminalSHA {
		return p, store.ErrCorrupt
	}
	_, e = Verify(Source{s.owner, day, uint64(p.Seq)}, event, p.TerminalSHA, 10, s.key.Public().(ed25519.PublicKey))
	if e == nil && s.holdsProtectDay(day, p.At) {
		return p, store.ErrCorrupt
	}
	return p, e
}

// finishOptionalDay は元journalの終端と全件回収を照合し、checkpoint先行の途中停止を再開する。
func (s *OptionalStore) finishOptionalDay(day uint64, p optionalCheckpoint) error {
	j := s.journals[day]
	if j == nil {
		return nil
	}
	if j.seq != uint64(p.TerminalSeq) || len(j.entries) == 0 || j.entries[len(j.entries)-1].Event.EventSHA != p.TerminalSHA {
		return store.ErrCorrupt
	}
	for _, entry := range j.entries {
		if entry.Event.Kind == "tombstone" {
			var t optionalTombstone
			if json.Unmarshal(entry.Payload, &t) != nil || t.At > p.At {
				return store.ErrCorrupt
			}
			continue
		}
		var payload OptionalPayload
		if !optionalKind(entry.Event.Kind) || json.Unmarshal(entry.Payload, &payload) != nil || payload.Record.Until > p.At || j.optionalHeld(payload.Record.ID, p.At) {
			return store.ErrCorrupt
		}
	}
	if e := j.Close(); e != nil {
		return e
	}
	if e := removeRetiredOptionalDirectory(j.dir); e != nil {
		return e
	}
	if e := store.SyncDirectory(s.root); e != nil {
		return e
	}
	delete(s.journals, day)
	return nil
}

// removeRetiredOptionalDirectory は署名済み全日回収の対象に限り、途中で欠けた固定名fileも回収する。
// 未知のfileやsubdirectoryを削除する救済は行わない。
func removeRetiredOptionalDirectory(dir string) error {
	info, e := os.Lstat(dir)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return store.ErrCorrupt
	}
	entries, e := os.ReadDir(dir)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		if entry.Name() != "control.current" && entry.Name() != ".optional-prune.snapshot" && optionalControlName.FindString(entry.Name()) == "" {
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
	for _, entry := range entries {
		if e = os.Remove(filepath.Join(dir, entry.Name())); e != nil {
			return e
		}
	}
	if e = store.SyncDirectory(dir); e != nil {
		return e
	}
	if e = os.Remove(dir); e != nil {
		return e
	}
	return store.SyncDirectory(filepath.Dir(dir))
}

func optionalCheckpointDay(name string) (uint64, error) {
	dayText, ok := strings.CutSuffix(name, ".checkpoint.json")
	if !ok || len(dayText) != 8 {
		return 0, store.ErrCorrupt
	}
	if _, e := time.Parse("20060102", dayText); e != nil {
		return 0, store.ErrCorrupt
	}
	day, e := strconv.ParseUint(dayText, 10, 64)
	return day, e
}

// openOptionalCheckpoints は固定名の署名を検査し、read-only検査では未完了dirを変更しない。
func (s *OptionalStore) openOptionalCheckpoints(entries []os.DirEntry, readOnly bool) error {
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		day, e := optionalCheckpointDay(entry.Name())
		if e != nil {
			return e
		}
		p, e := s.readOptionalCheckpoint(filepath.Join(s.root, entry.Name()), day)
		if e != nil {
			return e
		}
		s.floor = max(s.floor, p.At)
		if s.journals[day] != nil {
			if readOnly {
				return store.ErrIncomplete
			}
			if e = s.finishOptionalDay(day, p); e != nil {
				return e
			}
		}
	}
	for _, j := range s.journals {
		for _, entry := range j.entries {
			if entry.Event.Kind == "tombstone" {
				t, e := j.decodeOptionalTombstone(entry.Payload)
				if e != nil {
					return e
				}
				s.floor = max(s.floor, t.At)
			}
		}
	}
	return nil
}

// expireOptionalCheckpoints は本人情報のない日終端証跡を30日後に回収する。
func (s *OptionalStore) expireOptionalCheckpoints(now domain.Time) error {
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return e
	}
	changed := false
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		day, e := optionalCheckpointDay(entry.Name())
		if e != nil {
			return e
		}
		path := filepath.Join(s.root, entry.Name())
		p, e := s.readOptionalCheckpoint(path, day)
		if e != nil {
			return e
		}
		if now < p.Until {
			continue
		}
		if e = os.Remove(path); e != nil {
			return e
		}
		changed = true
	}
	if changed {
		return store.SyncDirectory(s.root)
	}
	return nil
}

// resumeOptionalCheckpointCandidates は設置前候補を原本と照合し、署名済み候補だけを設置する。
// 不完全なtmpは健全な日別原本が残っている場合だけ回収し、検査では一切変更しない。
func (s *OptionalStore) resumeOptionalCheckpointCandidates(readOnly bool) error {
	entries, e := os.ReadDir(s.root)
	if e != nil {
		return e
	}
	for _, entry := range entries {
		canonicalName, ok := strings.CutSuffix(entry.Name(), ".checkpoint.json.tmp")
		if !ok {
			continue
		}
		day, e := optionalCheckpointDay(canonicalName + ".checkpoint.json")
		if e != nil {
			return e
		}
		candidate := filepath.Join(s.root, entry.Name())
		raw, e := readOptionalPrivate(candidate, 16<<10)
		if e != nil {
			return e
		}
		canonical := strings.TrimSuffix(candidate, ".tmp")
		if saved, err := readOptionalPrivate(canonical, 16<<10); err == nil {
			if !bytes.Equal(saved, raw) {
				return store.ErrCorrupt
			}
			if _, err = s.readOptionalCheckpoint(canonical, day); err != nil {
				return err
			}
			if readOnly {
				return store.ErrIncomplete
			}
			if e = os.Remove(candidate); e != nil {
				return e
			}
			if e = store.SyncDirectory(s.root); e != nil {
				return e
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		dir := filepath.Join(s.root, canonicalName)
		if e = inspectOptionalDayNames(dir); e != nil {
			return e
		}
		j := &Journal{dir: dir, owner: s.owner, day: day, keyID: 10, key: s.key, validate: s.validate}
		state, e := store.InspectControl(dir, 8, s.owner, day, j.validateValue)
		if e != nil {
			return e
		}
		if e = j.replayState(state); e != nil {
			return e
		}
		p, validation := s.readOptionalCheckpoint(candidate, day)
		if validation == nil {
			if j.seq != uint64(p.TerminalSeq) || len(j.entries) == 0 || j.entries[len(j.entries)-1].Event.EventSHA != p.TerminalSHA {
				return store.ErrCorrupt
			}
			for _, row := range j.entries {
				if row.Event.Kind == "tombstone" {
					var t optionalTombstone
					if json.Unmarshal(row.Payload, &t) != nil || t.At > p.At {
						return store.ErrCorrupt
					}
					continue
				}
				var v OptionalPayload
				if !optionalKind(row.Event.Kind) || json.Unmarshal(row.Payload, &v) != nil || v.Record.Until > p.At {
					return store.ErrCorrupt
				}
			}
		}
		if readOnly {
			return store.ErrIncomplete
		}
		if validation != nil {
			// canonical未設置なので日別原本の回収は未開始。健全な原本だけを保持する。
			if e = os.Remove(candidate); e != nil {
				return e
			}
		} else {
			if e = os.Rename(candidate, canonical); e != nil {
				return e
			}
		}
		if e = store.SyncDirectory(s.root); e != nil {
			return e
		}
	}
	return nil
}
