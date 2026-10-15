// 必須記録の個別署名と既存frame形式を保ち、連続したイベントを一度で同期する。
package evidence

import (
	"bytes"
	"encoding/json"
	"oimobbs/internal/domain"
	"oimobbs/internal/store"
)

// AppendRequest は所有journalの確定seqを使って生成する、一つの必須記録候補。
type AppendRequest struct {
	ID        domain.ID
	Kind      string
	Committed domain.Time
	Build     func(Source) ([]byte, error)
}

// BatchReady は作成済みで追記可能なjournalかを所有列上で返す。
// 新規日別journalは従来の作成手順で先に確定する。
func (j *Journal) BatchReady() bool { return j.log != nil && !j.stopped }

// CommitStats は作成済みjournalのWAL保存呼出し数を返す。本文と秘密を含まない。
func (j *Journal) CommitStats() store.CommitStats {
	if j.log == nil {
		return store.CommitStats{}
	}
	return j.log.CommitStats()
}

// AppendBatch は全候補を検証・個別署名し、一度のSync後だけ履歴へ反映する。
// 既存の最大64frame/8MiB上限を保つ。作成前journalと回収操作には使わない。
func (j *Journal) AppendBatch(requests []AppendRequest) ([]Event, store.CommitResult) {
	fail := func(e error) ([]Event, store.CommitResult) {
		return nil, store.CommitResult{Status: store.NotWritten, Err: e}
	}
	if !j.BatchReady() || len(requests) == 0 || len(requests) > store.MaxCommitFrames {
		return fail(store.ErrCorrupt)
	}
	frames := make([][]byte, 0, len(requests))
	entries := make([]Entry, 0, len(requests))
	seen := make(map[domain.ID]bool, len(requests))
	var previous domain.Hash
	if len(j.entries) > 0 {
		previous = j.entries[len(j.entries)-1].Event.EventSHA
	}
	for i, request := range requests {
		if request.Build == nil || request.Kind == "tombstone" || j.ids[request.ID] || seen[request.ID] {
			return fail(store.ErrCorrupt)
		}
		seen[request.ID] = true
		seq := j.seq + uint64(i) + 1
		if seq <= j.seq {
			return fail(store.ErrCorrupt)
		}
		source := Source{j.owner, j.day, seq}
		payload, e := request.Build(source)
		if e != nil {
			return fail(e)
		}
		if e = j.validatePayload(request.Kind, payload); e != nil {
			return fail(e)
		}
		event, e := Seal(source, request.ID, request.Kind, payload, previous, j.keyID, j.key)
		if e != nil {
			return fail(e)
		}
		value, e := json.Marshal(event)
		if e != nil {
			return fail(e)
		}
		op := store.ControlOperation{Schema: 1, Seq: domain.U64(seq), ExpectedSeq: domain.U64(seq - 1), Committed: request.Committed, Actor: domain.Actor{Kind: "system", Reason: "evidence"}, Mutations: []store.Mutation{{Collection: request.Kind, Key: request.ID.String(), Value: value}}, Result: store.ControlResult{Code: "evidence_saved", Targets: []string{request.ID.String()}}}
		raw, e := json.Marshal(op)
		if e != nil {
			return fail(e)
		}
		frame, e := store.EncodeFrame(store.Frame{FirstSeq: seq, Records: []store.Record{{ID: request.ID, JSON: raw}}})
		if e != nil {
			return fail(e)
		}
		frames = append(frames, frame)
		entries = append(entries, Entry{event, bytes.Clone(payload)})
		previous = event.EventSHA
	}
	result := j.log.AppendBatch(frames)
	if result.Status == store.Unknown {
		j.stopped = true
	}
	if result.Status != store.Durable {
		return nil, result
	}
	events := make([]Event, len(entries))
	j.seq += uint64(len(entries))
	for i, entry := range entries {
		j.rememberRetention(entry.Payload)
		j.rememberCheckpointFloor(entry.Event, entry.Payload)
		j.ids[entry.Event.RecordID] = true
		events[i] = entry.Event
	}
	j.entries = append(j.entries, entries...)
	j.entryIndex = nil
	return events, result
}
