// 日別HTTP記録を既存の署名frameのまままとめて同期する。
package evidence

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

const MaxOptionalBatch = store.MaxCommitFrames

// OptionalBatchReservationは署名・base64・操作frameを含む保守的な予約量を返す。
// レコードのJSONサイズ制限も再確認し、不正な入力では保存を開始しない。
func OptionalBatchReservation(records []OptionalRecord) (int64, error) {
	if len(records) == 0 || len(records) > MaxOptionalBatch {
		return 0, store.ErrCorrupt
	}
	// 初回intentとWAL/currentの同時保持分も共通余力へ予約する。
	total := int64(256 << 10)
	for _, r := range records {
		raw, e := json.Marshal(r)
		if e != nil || len(raw) > MaxOptionalRecordBytes {
			return 0, store.ErrCorrupt
		}
		total += int64(len(raw)*2 + 2048)
	}
	return total, nil
}

// appendOptionalBatchは作成済み日別journalへ連続したsource/署名連鎖を保存する。
// 各記録は独立したframeを保ち、保存失敗時は稼働中の履歴を更新しない。
func (j *Journal) appendOptionalBatch(records []OptionalRecord, capacity func(int64) error) store.CommitResult {
	fail := func(e error) store.CommitResult { return store.CommitResult{Status: store.NotWritten, Err: e} }
	if j.stopped || j.log == nil || capacity == nil || len(records) == 0 || len(records) > MaxOptionalBatch {
		return fail(store.ErrCorrupt)
	}
	frames := make([][]byte, 0, len(records))
	entries := make([]Entry, 0, len(records))
	seen := make(map[domain.ID]bool, len(records))
	var prev domain.Hash
	if len(j.entries) > 0 {
		prev = j.entries[len(j.entries)-1].Event.EventSHA
	}
	for i, record := range records {
		if j.ids[record.ID] || seen[record.ID] {
			return fail(store.ErrCorrupt)
		}
		seen[record.ID] = true
		seq := j.seq + uint64(i) + 1
		if seq <= j.seq {
			return fail(store.ErrCorrupt)
		}
		src := Source{j.owner, j.day, seq}
		kind := record.Kind
		if kind == "access" {
			kind = "receipt"
		}
		payload, e := json.Marshal(OptionalPayload{src.Owner, domain.U64(src.Subkey), domain.U64(src.Seq), record})
		if e != nil {
			return fail(e)
		}
		if e = j.validatePayload(kind, payload); e != nil {
			return fail(e)
		}
		event, e := Seal(src, record.ID, kind, payload, prev, j.keyID, j.key)
		if e != nil {
			return fail(e)
		}
		value, e := json.Marshal(event)
		if e != nil {
			return fail(e)
		}
		// イベントIDはframeとmutationと署名valueにあり、使われないresultへの重複を保存しない。結果codeも保存済みを表す固定値にする。
		op := store.ControlOperation{Schema: 1, Seq: domain.U64(seq), Committed: record.Finished, ExpectedSeq: domain.U64(seq - 1), Actor: domain.Actor{Kind: "system", Reason: "evidence"}, Mutations: []store.Mutation{{Collection: kind, Key: record.ID.String(), Value: value}}, Result: store.ControlResult{Code: "saved", Targets: []string{}}}
		raw, e := json.Marshal(op)
		if e != nil {
			return fail(e)
		}
		frame, e := store.EncodeFrame(store.Frame{FirstSeq: seq, Records: []store.Record{{ID: record.ID, JSON: raw}}})
		if e != nil {
			return fail(e)
		}
		frames = append(frames, frame)
		// Marshalが返した専有配列を保持し、同じ本文の再コピーを避ける。
		entries = append(entries, Entry{event, payload})
		prev = event.EventSHA
	}
	var size int64
	for _, frame := range frames {
		size += int64(len(frame))
	}
	if e := capacity(size); e != nil {
		return fail(e)
	}
	result := j.log.AppendBatch(frames)
	if result.Status == store.Unknown {
		j.stopped = true
	}
	if result.Status == store.Durable {
		j.seq += uint64(len(entries))
		for _, entry := range entries {
			j.rememberRetention(entry.Payload)
			j.rememberCheckpointFloor(entry.Event, entry.Payload)
			j.ids[entry.Event.RecordID] = true
		}
		j.entries = append(j.entries, entries...)
		j.entryIndex = nil
	}
	return result
}
