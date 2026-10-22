// 日別HTTP記録を既存の署名frameのまままとめて同期する。
package evidence

import (
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// MaxOptionalBatch は64frameの既存WAL block四個を、一度の同期へまとめる非必須記録数。
const MaxOptionalBatch = store.MaxCommitSeriesFrames

// 大きな記録でも、包み込み後の列全体を8MiB以内に保つ保守的な元JSON予算。
const maxOptionalBatchRecordBytes = 4 << 20

// OptionalBatchReservationは署名・base64・操作frameを含む保守的な予約量を返す。
// レコードのJSONサイズ制限も再確認し、不正な入力では保存を開始しない。
func OptionalBatchReservation(records []OptionalRecord) (int64, error) {
	count, reservation, err := optionalBatchPrefix(records)
	if err != nil {
		return 0, err
	}
	if count != len(records) {
		return 0, store.ErrCorrupt
	}
	return reservation, nil
}

// optionalBatchPrefix は全入力の符号化上限を検査し、元JSON予算内の連続区間だけを返す。
// Storeへの直接投入も、大きい行を落とさずに分割する。各行の最大長は従来と同じ。
func optionalBatchPrefix(records []OptionalRecord) (int, int64, error) {
	if len(records) == 0 || len(records) > MaxOptionalBatch {
		return len(records), 0, store.ErrCorrupt
	}
	sizes := make([]int, len(records))
	for i, record := range records {
		raw, err := json.Marshal(record)
		if err != nil || len(raw) > MaxOptionalRecordBytes {
			return len(records), 0, store.ErrCorrupt
		}
		sizes[i] = len(raw)
	}
	// Eventのbase64は4/3倍。元JSON4MiBと最大256件の包みを含め、実frameは8MiB未満。
	rawBytes, count := 0, 0
	for _, size := range sizes {
		if size > maxOptionalBatchRecordBytes-rawBytes {
			break
		}
		rawBytes += size
		count++
	}
	// バイト上限で区切る場合も既存64件blockの途中で切らず、圧縮単位を小さくしない。
	if count < len(records) {
		count = alignedOptionalCount(count)
	}
	total := int64(256 << 10)
	for _, size := range sizes[:count] {
		total += int64(size*2 + 2048)
	}
	if count == 0 {
		return len(records), 0, store.ErrCorrupt
	}
	return count, total, nil
}

// alignedOptionalCount は次の記録を持ち越す場合だけ、従来の圧縮単位へ切りそろえる。
func alignedOptionalCount(count int) int {
	if count >= store.MaxCommitFrames {
		return count / store.MaxCommitFrames * store.MaxCommitFrames
	}
	return count
}

// appendOptionalBatchは作成済み日別journalへ連続したsource/署名連鎖を保存する。
// 各記録は独立したframeを保ち、保存失敗時は稼働中の履歴を更新しない。
func (j *Journal) appendOptionalBatch(records []OptionalRecord, capacity func(int64, int64) error) store.CommitResult {
	fail := func(e error) store.CommitResult { return store.CommitResult{Status: store.NotWritten, Err: e} }
	if j.stopped || j.log == nil || capacity == nil || len(records) == 0 || len(records) > MaxOptionalBatch {
		return fail(store.ErrCorrupt)
	}
	j.preparedPayloads = make(map[domain.Hash]preparedPayload, len(records))
	defer func() { j.preparedPayloads = nil }()
	frames := make([][]byte, 0, len(records))
	entries := make([]Entry, 0, len(records))
	seen := make(map[domain.ID]bool, len(records))
	var retained int64
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
		retained += int64(len(value) + journalRowOverhead)
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
		entries = append(entries, retainJournalEntry(event, payload))
		j.preparedPayloads[event.PayloadSHA] = preparedPayload{kind, payload}
		prev = event.EventSHA
	}
	result := j.log.AppendSeriesChecked(frames, func(size int64) error { return capacity(size, retained) })
	if result.Status == store.Unknown {
		j.stopped = true
	}
	if result.Status == store.Durable {
		j.seq += uint64(len(entries))
		j.retainedBytes += retained
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
