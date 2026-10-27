// 所有列から明示的に渡された私的構築だけを、検証と同じCPU枠へ分担する。
package evidence

import (
	"bytes"
	"oimobbs/internal/domain"
	"oimobbs/internal/parallel"
	"oimobbs/internal/store"
)

// prepareParallelPayloads は全workerを待ってから元順序のエラーと合計byte上限を確認する。
// 共有bufferの書換えや所有状態の更新を行うBuildには使用しない。
func (j *Journal) prepareParallelPayloads(requests []AppendRequest) ([][]byte, []Event, error) {
	seen := make(map[domain.ID]bool, len(requests))
	for i, request := range requests {
		if request.Build == nil || request.Kind == "tombstone" || j.ids[request.ID] || seen[request.ID] || j.seq+uint64(i)+1 <= j.seq {
			return nil, nil, store.ErrCorrupt
		}
		seen[request.ID] = true
	}
	payloads := make([][]byte, len(requests))
	events := make([]Event, len(requests))
	errs := make([]error, len(requests))
	sealErrs := make([]error, len(requests))
	parallel.CPU(len(requests), func(i int) {
		request := requests[i]
		raw, err := request.Build(Source{j.owner, j.day, j.seq + uint64(i) + 1})
		if err != nil {
			errs[i] = err
			return
		}
		if len(raw) > 512<<10 {
			errs[i] = store.ErrCorrupt
			return
		}
		raw = bytes.Clone(raw)
		if err = j.validatePayload(request.Kind, raw); err != nil {
			errs[i] = err
			return
		}
		payloads[i] = raw
		// 同じslotのsource検査・hash・Base64まで続け、二度目のworker生成と全件待ちを省く。
		events[i], sealErrs[i] = prepareSeal(Source{j.owner, j.day, j.seq + uint64(i) + 1}, request.ID, request.Kind, raw, domain.Hash{}, j.keyID, j.key)
	})
	total := 0
	for i, raw := range payloads {
		if errs[i] != nil {
			return nil, nil, errs[i]
		}
		if len(raw) > (8<<20)-total {
			return nil, nil, store.ErrCorrupt
		}
		total += len(raw)
	}
	// payload検査と総量の失敗を先に返す従来の優先順を保つ。
	for _, err := range sealErrs {
		if err != nil {
			return nil, nil, err
		}
	}
	return payloads, events, nil
}
