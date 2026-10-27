// 必須記録の個別署名と既存frame形式を保ち、連続したイベントを一度で同期する。
package evidence

import (
	"bytes"
	"oimobbs/internal/domain"
	"oimobbs/internal/parallel"
	"oimobbs/internal/store"
	"runtime"
	"sync"
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
	return j.appendBatch(requests, false, false)
}

// AppendBatchConcurrent は所有列を保持したまま、独立payloadの検証・個別署名・符号化をCPU数以内で並行する。
// Buildは要求順に呼ぶ。validateは並行呼出し可能でなければならない。
// 全検証の成功後にだけ署名連鎖・WALを作り、一度のSync後に履歴を交換する。
func (j *Journal) AppendBatchConcurrent(requests []AppendRequest) ([]Event, store.CommitResult) {
	return j.appendBatch(requests, true, false)
}

// AppendBatchConcurrentBuild は所有列が専有する私的入力のBuildもCPU数以内へ分担する。
// Build/validateは並行呼出し可能とし、Buildは呼出しごとの私的な結果だけを書き込む。
// 最大64件・各payload512KiBの一時構築を許し、合計8MiBを確認してから連鎖と同期へ進む。
// 通常callbackの実行順序を保つAppendBatchConcurrentとは明示的に分ける。
func (j *Journal) AppendBatchConcurrentBuild(requests []AppendRequest) ([]Event, store.CommitResult) {
	return j.appendBatch(requests, true, true)
}

func (j *Journal) appendBatch(requests []AppendRequest, concurrent, parallelBuild bool) ([]Event, store.CommitResult) {
	fail := func(e error) ([]Event, store.CommitResult) {
		return nil, store.CommitResult{Status: store.NotWritten, Err: e}
	}
	if !j.BatchReady() || len(requests) == 0 || len(requests) > store.MaxCommitFrames {
		return fail(store.ErrCorrupt)
	}
	// 検査済み元byteはこの呼出しの最大64件だけで共有し、失敗時も持ち越さない。
	j.preparedPayloads = make(map[domain.Hash]preparedPayload, len(requests))
	defer func() { j.preparedPayloads = nil }()
	var payloads [][]byte
	var preparedEvents []Event
	if concurrent && len(requests) > 1 && runtime.GOMAXPROCS(0) > 1 {
		var err error
		if parallelBuild {
			payloads, preparedEvents, err = j.prepareParallelPayloads(requests)
		} else {
			payloads, err = j.prepareConcurrentPayloads(requests)
		}
		if err != nil {
			return fail(err)
		}
	}
	if payloads != nil && preparedEvents == nil {
		preparedEvents = make([]Event, len(requests))
		errs := make([]error, len(requests))
		parallel.CPU(len(requests), func(i int) {
			request := requests[i]
			preparedEvents[i], errs[i] = prepareSeal(Source{j.owner, j.day, j.seq + uint64(i) + 1}, request.ID, request.Kind, payloads[i], domain.Hash{}, j.keyID, j.key)
		})
		for _, err := range errs {
			if err != nil {
				return fail(err)
			}
		}
	}
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
		var payload []byte
		var e error
		if payloads != nil {
			payload = payloads[i]
		} else {
			payload, e = request.Build(source)
			if e != nil {
				return fail(e)
			}
			if e = j.validatePayload(request.Kind, payload); e != nil {
				return fail(e)
			}
		}
		var event Event
		if preparedEvents != nil {
			event = preparedEvents[i]
			event.PreviousSHA = previous
			event.EventSHA = digest(source, request.ID, request.Kind, event.PayloadSHA, previous)
		} else {
			event, e = prepareSeal(source, request.ID, request.Kind, payload, previous, j.keyID, j.key)
			if e != nil {
				return fail(e)
			}
		}
		if payloads == nil {
			payload = bytes.Clone(payload)
		} else {
			payloads[i] = nil
		}
		entries = append(entries, Entry{event, payload})
		previous = event.EventSHA
	}
	frames, err := j.prepareBatchFrames(entries, requests, concurrent)
	if err != nil {
		return fail(err)
	}
	for i, entry := range entries {
		j.preparedPayloads[entry.Event.PayloadSHA] = preparedPayload{kind: requests[i].Kind, raw: entry.Payload, source: Source{j.owner, j.day, j.seq + uint64(i) + 1}}
	}

	var result store.CommitResult
	if concurrent {
		result = j.log.AppendIndependentBatch(frames)
	} else {
		result = j.log.AppendBatch(frames)
	}
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
		entries[i] = retainJournalEntry(entry.Event, entry.Payload)
	}
	j.entries = append(j.entries, entries...)
	j.entryIndex = nil
	return events, result
}

// prepareConcurrentPayloads はcallbackを順序通り実行し、コピーした元byteの検査だけを並行する。
// journalの可変状態には書き込まず、全workerを待ってから要求順の最初のエラーを返す。
func (j *Journal) prepareConcurrentPayloads(requests []AppendRequest) ([][]byte, error) {
	payloads := make([][]byte, len(requests))
	seen := make(map[domain.ID]bool, len(requests))
	total := 0
	for i, request := range requests {
		if request.Build == nil || request.Kind == "tombstone" || j.ids[request.ID] || seen[request.ID] || j.seq+uint64(i)+1 <= j.seq {
			return nil, store.ErrCorrupt
		}
		seen[request.ID] = true
		payload, err := request.Build(Source{j.owner, j.day, j.seq + uint64(i) + 1})
		if err != nil {
			return nil, err
		}
		// 最終frameも8MiB以内なので、元payloadだけで上限を超える群は保持しない。
		if len(payload) > 512<<10 || len(payload) > (8<<20)-total {
			return nil, store.ErrCorrupt
		}
		total += len(payload)
		payloads[i] = bytes.Clone(payload)
	}
	errs := make([]error, len(requests))
	var workers sync.WaitGroup
	count := min(len(requests), runtime.GOMAXPROCS(0))
	for worker := range count {
		workers.Go(func() {
			for i := worker; i < len(requests); i += count {
				errs[i] = j.validatePayload(requests[i].Kind, payloads[i])
			}
		})
	}
	workers.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return payloads, nil
}
