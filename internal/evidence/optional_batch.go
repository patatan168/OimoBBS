// 日別HTTP記録を既存の署名frameのまままとめて同期する。
package evidence

import (
	"crypto/ed25519"
	"encoding/base64"
	"oimobbs/internal/domain"
	"oimobbs/internal/parallel"
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
		raw, err := MarshalOptionalRecord(record)
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
	entries, frames, retained, err := j.prepareOptionalBatch(records)
	if err != nil {
		return fail(err)
	}
	for i, entry := range entries {
		j.preparedPayloads[entry.Event.PayloadSHA] = preparedPayload{kind: entry.Event.Kind, raw: entry.Payload, source: Source{j.owner, j.day, j.seq + uint64(i) + 1}}
	}
	result := j.log.AppendIndependentSeriesChecked(frames, func(size int64) error { return capacity(size, retained) })
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

// prepareOptionalBatch は有界な群のJSON化・完全検査・署名・frame生成をCPU数以内で分担する。
// 連番と直前hashだけを所有列で接続し、全workerの完了までは状態もWALも変更しない。
func (j *Journal) prepareOptionalBatch(records []OptionalRecord) ([]Entry, [][]byte, int64, error) {
	seen := make(map[domain.ID]bool, len(records))
	for i, record := range records {
		if j.ids[record.ID] || seen[record.ID] || j.seq+uint64(i)+1 <= j.seq {
			return nil, nil, 0, store.ErrCorrupt
		}
		seen[record.ID] = true
	}
	entries := make([]Entry, len(records))
	errs := make([]error, len(records))
	parallel.CPU(len(records), func(i int) {
		record := records[i]
		source := Source{j.owner, j.day, j.seq + uint64(i) + 1}
		kind := record.Kind
		if kind == "access" {
			kind = "receipt"
		}
		payload, err := MarshalOptionalPayload(OptionalPayload{source.Owner, domain.U64(source.Subkey), domain.U64(source.Seq), record})
		if err == nil {
			err = j.validatePayload(kind, payload)
		}
		if err != nil {
			errs[i] = err
			return
		}
		event, err := prepareSeal(source, record.ID, kind, payload, domain.Hash{}, j.keyID, j.key)
		entries[i] = Entry{Event: event, Payload: payload}
		errs[i] = err
	})
	for _, err := range errs {
		if err != nil {
			return nil, nil, 0, err
		}
	}
	var previous domain.Hash
	if len(j.entries) > 0 {
		previous = j.entries[len(j.entries)-1].Event.EventSHA
	}
	for i := range entries {
		event := &entries[i].Event
		event.PreviousSHA = previous
		event.EventSHA = digest(Source{j.owner, j.day, j.seq + uint64(i) + 1}, event.RecordID, event.Kind, event.PayloadSHA, previous)
		previous = event.EventSHA
	}
	frames := make([][]byte, len(records))
	sizes := make([]int64, len(records))
	parallel.CPU(len(records), func(i int) {
		event := &entries[i].Event
		signature := ed25519.Sign(j.key, event.EventSHA[:])
		event.Signature = base64.StdEncoding.EncodeToString(signature)
		seq := j.seq + uint64(i) + 1
		record := records[i]
		raw, valueSize, err := marshalJournalOperation(*event, entries[i].Payload, signature, seq, record.Finished, true)
		if err != nil {
			errs[i] = err
			return
		}
		sizes[i] = int64(valueSize + journalRowOverhead)
		frames[i], errs[i] = store.EncodeFrame(store.Frame{FirstSeq: seq, Records: []store.Record{{ID: record.ID, JSON: raw}}})
		entries[i] = retainJournalEntry(*event, entries[i].Payload)
	})
	var retained int64
	for i, err := range errs {
		if err != nil {
			return nil, nil, 0, err
		}
		retained += sizes[i]
	}
	return entries, frames, retained, nil
}
