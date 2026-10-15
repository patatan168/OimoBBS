// 日別の署名済み末尾・件数・時計床を、本文なしチェックポイントへ固定する。
package evidence

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
	"oimobbs/internal/strictjson"
	"time"
)

// JournalCheckpoint は確認済みprefixの終端。欠落ゼロや外部時刻証明として扱わない。
type JournalCheckpoint struct {
	Schema           string      `json:"schema"`
	Owner            domain.ID   `json:"source_owner_id"`
	Day              domain.U64  `json:"source_subkey"`
	Sequence         domain.U64  `json:"source_control_seq"`
	TerminalSequence domain.U64  `json:"terminal_seq"`
	TerminalSHA      domain.Hash `json:"terminal_event_sha256"`
	Count            domain.U64  `json:"event_count"`
	At               domain.Time `json:"checkpoint_at_ns"`
	ClockFloor       domain.Time `json:"required_clock_floor_ns"`
}

// Checkpoint はUTC日末後に最新prefixをSyncする。既に最新なら同じ署名を返す。
// 呼出元はreader55の先行保存と所有排他を確保し、外部境界へ保存する場合は別途認可する。
func (j *Journal) Checkpoint(now time.Time) (Event, error) {
	if j.stopped || j.seq == 0 || len(j.entries) == 0 {
		return Event{}, store.ErrIncomplete
	}
	if e := j.checkCheckpointTime(domain.Time(now.UnixNano())); e != nil {
		return Event{}, e
	}
	last := j.entries[len(j.entries)-1].Event
	if last.Kind == "journal_checkpoint" {
		return last, nil
	}
	p := JournalCheckpoint{Schema: "required-journal-checkpoint-v1", Owner: j.owner, Day: domain.U64(j.day), Sequence: domain.U64(j.seq + 1), TerminalSequence: domain.U64(j.seq), TerminalSHA: last.EventSHA, Count: domain.U64(j.seq), At: domain.Time(now.UnixNano()), ClockFloor: j.requiredFloor}
	raw, e := json.Marshal(p)
	if e != nil {
		return Event{}, e
	}
	hash := sha256.Sum256(append([]byte("oimo/required-journal-checkpoint/v1"), raw...))
	var id domain.ID
	copy(id[:], hash[:16])
	event, result := j.Append(id, "journal_checkpoint", p.At, func(Source) ([]byte, error) { return raw, nil })
	if result.Status != store.Durable {
		return event, result.Err
	}
	return event, nil
}

// CheckpointPending はUTC日末後の未固定prefixだけを報告する。空列を作らない。
func (j *Journal) CheckpointPending(now time.Time) bool {
	return j.seq != 0 && len(j.entries) != 0 && j.entries[len(j.entries)-1].Event.Kind != "journal_checkpoint" && j.checkCheckpointTime(domain.Time(now.UnixNano())) == nil
}

// DecodeJournalCheckpoint は完全型と内部prefix対応を検査する。署名は別途Verifyする。
func DecodeJournalCheckpoint(raw []byte) (JournalCheckpoint, error) {
	var p JournalCheckpoint
	if e := strictjson.Decode(raw, &p); e != nil {
		return p, e
	}
	if !validJournalCheckpointPrefix(p) {
		return p, store.ErrCorrupt
	}
	if p.ClockFloor < 0 || p.ClockFloor > p.At {
		return p, store.ErrCorrupt
	}
	j := Journal{day: uint64(p.Day), requiredFloor: p.ClockFloor}
	if e := j.checkCheckpointTime(p.At); e != nil {
		return p, e
	}
	return p, nil
}

// checkCheckpointTime はUTC日末と現在の署名済み時計床を検査する。
func (j *Journal) checkCheckpointTime(at domain.Time) error {
	day, e := time.Parse("20060102", fmt.Sprint(j.day))
	if e != nil {
		return store.ErrCorrupt
	}
	if at < domain.Time(day.AddDate(0, 0, 1).UnixNano()) || at < j.requiredFloor {
		return ErrRetirementClock
	}
	return nil
}

// validateCheckpointEntry は実署名列の一つ前のhash/seqとcheckpointの対象を一致させる。
func validateCheckpointEntry(event Event, payload []byte) error {
	if event.Kind != "journal_checkpoint" {
		return nil
	}
	p, e := DecodeJournalCheckpoint(payload)
	if e != nil {
		return e
	}
	if p.TerminalSHA != event.PreviousSHA {
		return store.ErrCorrupt
	}
	return nil
}

// LatestCheckpoint は最後にSyncした日末署名を返す。未固定の後続行があっても前の確認境界を保つ。
func (j *Journal) LatestCheckpoint() (Event, bool) {
	for i := len(j.entries) - 1; i >= 0; i-- {
		if j.entries[i].Event.Kind == "journal_checkpoint" {
			return j.entries[i].Event, true
		}
	}
	return Event{}, false
}

// VerifyJournalCheckpoint は保存した末尾署名の完全型・所有者位置・鍵を照合する。
func VerifyJournalCheckpoint(event Event, key ed25519.PublicKey) (JournalCheckpoint, error) {
	raw, e := decodePayload(event)
	if e != nil {
		return JournalCheckpoint{}, e
	}
	p, e := DecodeJournalCheckpoint(raw)
	if e != nil {
		return p, e
	}
	if event.Kind != "journal_checkpoint" {
		return p, store.ErrCorrupt
	}
	_, e = Verify(Source{p.Owner, uint64(p.Day), uint64(p.Sequence)}, event, p.TerminalSHA, 10, key)
	return p, e
}

// validJournalCheckpointPrefix は空列/桁あふれを含む内部位置の矛盾を拒否する。
func validJournalCheckpointPrefix(p JournalCheckpoint) bool {
	return p.Schema == "required-journal-checkpoint-v1" && p.Owner != (domain.ID{}) && p.TerminalSequence != 0 && p.Sequence != 0 && p.Sequence == p.TerminalSequence+1 && p.Count == p.TerminalSequence && p.TerminalSHA != (domain.Hash{})
}
